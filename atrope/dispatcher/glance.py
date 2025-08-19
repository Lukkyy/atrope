# -*- coding: utf-8 -*-

# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json

import yaml
from keystoneauth1 import loading
from openstack import connection
from openstack.exceptions import ConflictException, ForbiddenException, HttpException
from oslo_config import cfg
from oslo_log import log

from atrope import exception
from atrope.dispatcher import base

CONF = cfg.CONF
CFG_GROUP = "glance"
CONF.import_opt("prefix", "atrope.dispatcher.manager", group="dispatchers")
opts = [
    cfg.ListOpt(
        "formats",
        default=[],
        help="Formats to covert images to. Empty for no " "conversion.",
    ),
    cfg.StrOpt(
        "vo_map",
        default="/etc/atrope/vo_map.yaml",
        help="Where the map from VO to projects is stored.",
    ),
    cfg.StrOpt(
        "tag",
        default="atrope",
        help="Tag set on images managed by atrope.",
    ),
]
CONF.register_opts(opts, group=CFG_GROUP)

loading.register_auth_conf_options(CONF, CFG_GROUP)
loading.register_session_conf_options(CONF, CFG_GROUP)
loading.register_adapter_conf_options(CONF, CFG_GROUP)

opts = (
    loading.get_auth_common_conf_options()
    + loading.get_session_conf_options()
    + loading.get_auth_plugin_conf_options("password")
    + loading.get_adapter_conf_options()
)

LOG = log.getLogger(__name__)


class Dispatcher(base.BaseDispatcher):
    """Glance dispatcher.

    This dispatcher will upload images to a glance catalog. The images are
    uploaded, and some metadata is associated to them so as to distinguish
    them from normal images:

        - all images will be tagged with the tag set in the configuration ("atrope").
        - the following properties will be set:
            - "image_hash": will contain the checksum for the image.
            - "vmcatcher_event_dc_description": will contain the appdb
              description
            - "vmcatcher_event_ad_mpuri": will contain the marketplate uri
            - "appdb_id": will contain the AppDB UUID
            - "APPLIANCE_ATTRIBUTES": will contain the original data from
               the Hepix description as json if available
            - "disk_format": as defined by the image or the converted format
              supported by the site
            - "container_format": set as 'bare'

    Moreover, some glance property keys will be set (if available):
        - os_version
        - os_distro
        - architecture
    """

    property_map = {
        "os_version": "osversion",
        "os_distro": "osname",
        "architecture": "arch",
    }

    def __init__(self):
        self.client = self._get_openstack_client()
        self.vo_map = self._read_vo_map()

    def _get_openstack_client(self, project_id=None):
        if project_id:
            auth_plugin = loading.load_auth_from_conf_options(
                CONF, CFG_GROUP, project_id=project_id
            )
        else:
            auth_plugin = loading.load_auth_from_conf_options(CONF, CFG_GROUP)

        session = loading.load_session_from_conf_options(
            CONF, CFG_GROUP, auth=auth_plugin
        )
        conn = connection.Connection(
            session=session,
            oslo_conf=CONF,
        )
        return conn

    def _read_vo_map(self):
        try:
            with open(CONF.glance.vo_map, "rb") as f:
                vo_map = yaml.safe_load(f) or {}
        except IOError as e:
            raise exception.CannotOpenFile(file=CONF.glance.vo_map, errno=e.errno)
        return vo_map

    def _clean_stale_memberships(self, image_id, vos, visibility):
        self.client.image.update_image(image_id, visibility="shared")
        current_projects = {self.vo_map.get(vo, {}).get("project_id", "") for vo in vos}
        members = self.client.image.members(image_id)
        for member in members:
            if member.member_id not in current_projects:
                self.client.image.remove_member(image_id, member.member_id)
                LOG.info(
                    "Image '%s' not associated with project '%s' anymore, stopped sharing",
                    image_id,
                    member.member_id,
                )
        self.client.image.update_image(image_id, visibility=visibility)

    def _share_image(self, image, glance_image, project):
        try:
            self.client.image.add_member(glance_image.id, member_id=project)
        except ConflictException:
            LOG.debug(
                "Image '%s' already associated with project '%s'",
                image.identifier,
                project,
            )
        finally:
            client = self._get_openstack_client(project_id=project)
            client.image.update_member(
                member=project, image=glance_image.id, status="accepted"
            )

            LOG.info(
                "Image '%s' associated with project '%s'",
                image.identifier,
                project,
            )

    def dispatch(self, image_name, image, sharing_model, **kwargs):
        """Upload an image to the glance service.

        If metadata is provided in the kwargs it will be associated with
        the image.
        """
        LOG.info("Glance dispatching '%s'", image.identifier)

        vos = kwargs.pop("vos")
        if vos:
            sharing_model = "shared"

        # TODO(aloga): missing hypervisor type, need list spec first
        metadata = {
            "name": image_name,
            "tags": [CONF.glance.tag],
            "visibility": sharing_model,
            # AppDB properties
            "vmcatcher_event_dc_description": getattr(image, "description", ""),
            "vmcatcher_event_ad_mpuri": image.mpuri,
            "appdb_id": image.identifier,
            "image_hash": image.hash,
        }

        # Optional attributes
        for prop, attr in self.property_map.items():
            value = getattr(image, attr, None)
            if value:
                metadata[prop] = value

        appliance_attrs = getattr(image, "appliance_attributes")
        if appliance_attrs:
            metadata["APPLIANCE_ATTRIBUTES"] = json.dumps(appliance_attrs)

        for k, v in kwargs.items():
            if k in metadata:
                raise exception.MetadataOverwriteNotSupported(key=k)
            metadata[k] = v

        images = [
            img
            for img in self.client.image.images(tag=CONF.glance.tag)
            if img.properties.get("appdb_id", "") == image.identifier
        ]
        if len(images) > 1:
            images = [img.id for img in images]
            LOG.error(
                "Found several images with same hash, please remove "
                "them manually and run atrope again: %s",
                images,
            )
            raise exception.DuplicatedImage(images=images)

        try:
            glance_image = images.pop()
        except IndexError:
            glance_image = None
        else:
            if glance_image.properties.get("image_hash", "") != image.hash:
                LOG.warning(
                    "Image '%s' is '%s' in glance but checksums"
                    "are different, deleting it and reuploading.",
                    image.identifier,
                    glance_image.id,
                )
                self.client.image.delete_image(glance_image.id)
                glance_image = None

        metadata["disk_format"], image_fd = image.convert(CONF.glance.formats)
        metadata["disk_format"] = metadata["disk_format"].lower()
        if metadata["disk_format"] not in [
            "ami",
            "ari",
            "aki",
            "vhd",
            "vhdx",
            "vmdk",
            "raw",
            "qcow2",
            "vdi",
            "iso",
            "ploop",
            "root-tar",
        ]:
            metadata["disk_format"] = "raw"
        metadata["container_format"] = (
            "bare" if metadata["disk_format"] not in ["vmdk"] else "ova"
        )

        if not glance_image:
            LOG.debug("Creating image '%s'.", image.identifier)
            try:
                glance_image = self.client.image.create_image(
                    **metadata, allow_duplicates=True
                )
            except ForbiddenException as e:
                LOG.error("Insufficient permissions to create Image in Glance")
                raise exception.GlancePermissionError(action=e)

        if glance_image.status == "queued":
            LOG.debug("Uploading image '%s'.", image.identifier)
            glance_image.upload(self.client.image, data=image_fd)

        if glance_image.status == "active":
            if glance_image.visibility != sharing_model:
                LOG.info("Set image '%s' as '%s'", image.identifier, sharing_model)
                try:
                    self.client.image.update_image(
                        glance_image.id, visibility=sharing_model
                    )
                except ForbiddenException as e:
                    LOG.error("Insufficient permissions to update Image in Glance")
                    raise exception.GlancePermissionError(action=e)
            LOG.info(
                "Image '%s' stored in glance as '%s'.",
                image.identifier,
                glance_image.id,
            )

        if sharing_model == "shared":
            for vo in vos:
                project = self.vo_map.get(vo, {}).get("project_id", "")
                if not project:
                    LOG.warning(
                        "No project associated with VO '%s', image won't be shared.", vo
                    )
                    continue
                if glance_image.owner == project:
                    LOG.info(
                        "Image '%s' owned by dest project %s.",
                        image.identifier,
                        project,
                    )
                else:
                    if glance_image.visibility != "shared":
                        LOG.debug("Set image '%s' as shared", image.identifier)
                        sharing_model = "shared"
                        self.client.image.update_image(
                            glance_image.id, visibility="shared"
                        )
                    self._share_image(
                        image=image, glance_image=glance_image, project=project
                    )

            self._clean_stale_memberships(glance_image.id, vos, sharing_model)

    def sync(self, image_list):
        """Sync image list with dispatched images.

        This method will remove images that were not set to be dispatched
        (i.e. that are not included in the list) that are present in Glance.
        """
        valid_images = [i.identifier for i in image_list.get_valid_subscribed_images()]
        for image in self.client.image.images(tag=CONF.glance.tag):
            if image.properties.get("image_list", "") != image_list.name:
                continue
            appdb_id = image.properties.get("appdb_id", "")
            if appdb_id not in valid_images:
                LOG.warning(
                    "Glance image '%s' is not valid anymore, " "deleting it", image.id
                )
                try:
                    self.client.image.delete_image(image.id)
                    LOG.info("Successfully deleted image '%s'", image.id)
                except HttpException as e:
                    LOG.warning(
                        "Failed to delete Glance image '%s': %s. "
                        "Making it private and deactivating it instead.",
                        image.id,
                        e,
                    )
                    self.client.image.update_image(image.id, visibility="private")
                    self.client.image.deactivate_image(image.id)
        LOG.info("Sync terminated for image list '%s'", image_list.name)

    def _upload(self, id, image_fd):
        self.client.image.upload(id, image_fd)
