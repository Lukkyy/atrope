# -*- coding: utf-8 -*-

# Copyright 2014 Alvaro Lopez Garcia
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc
import datetime
import os.path
import subprocess
import tempfile

import dateutil.parser
import dateutil.tz
from oslo_config import cfg
from oslo_log import log
import requests
import requests.certs
import six

from atrope import exception
from atrope import ovf
from atrope import paths
from atrope import utils

opts = [
    cfg.StrOpt(
        "download_ca_file",
        default=paths.state_path_def("atrope-ca-bundle.pem"),
        help="Atrope will build a CA bundle for verifying the "
        "HTTP servers when it is downloading the image, "
        "concatenating the default OS CA bundle and the "
        "CAs present in the $ca_path directory. This "
        "is done as there may be certificates signed by "
        "CAs that are trusted by the provider, but untrusted "
        "by the default bundle and we need to trust both.",
    ),
]

CONF = cfg.CONF
CONF.register_opts(opts)
CONF.import_opt("ca_path", "atrope.smime")

LOG = log.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class BaseImage(object):
    @abc.abstractmethod
    def __init__(self, image_info):
        self.uri = None
        self.sha512 = None
        self.identifier = None
        self.location = None
        self.locations = []
        self.verified = False
        self.expired = False

    @abc.abstractmethod
    def download(self, dest):
        """Download the image.

        :param dest: destionation directory.
        """

    def get_file(self, mode="rb"):
        """Return a File object containing the downloaded file."""
        return open(self.location, mode)

    def get_kernel(self):
        raise NotImplementedError()

    def get_ramdisk(self):
        raise NotImplementedError()

    def get_disk(self):
        """Return the format and a 'ro' File-like object containing the disk.

        Images can be stored in containers like OVA, this method will return a
        tuple (format, fd) being 'format' a string containing the image disk
        format and 'fd' File-like object containing the original image disk as
        extracted from the container.

        We assume that containers only store one image disk. We scan the file
        in reverse order, as OVF specification states that files can be
        appended so as to update the OVF file.
        """
        if self.format.lower() != "ova":
            return self.format, self.get_file()

        ovf_file = ovf.get_ovf(self.location)

        fmt, disk_filename = ovf.get_disk_name(ovf_file)
        disk_fd = ovf.extract_file(self.location, disk_filename)
        return fmt, disk_fd

    def verify_checksum(self, location=None):
        """Verify the image's checksum."""
        LOG.info(
            "Image '%s' present in '%s', verifying checksum", self.identifier, location
        )

        location = location or self.location
        if location is None:
            raise exception.ImageNotFoundOnDisk(location=location)

        sha512 = utils.get_file_checksum(location)
        if sha512.hexdigest() != self.sha512:
            raise exception.ImageVerificationFailed(
                id=self.identifier, expected=self.sha512, obtained=sha512.hexdigest()
            )
        LOG.info("Image '%s' present in '%s', checksum OK", self.identifier, location)
        self.verified = True

    def convert(self, dest_formats=[], mode="rb"):
        fmt, disk = self.get_disk()
        if (not dest_formats) or (fmt.lower() in dest_formats):
            LOG.debug("No need to convert initial image format '%s'", fmt)
            return fmt, disk
        # extract the file to disk and convert to the first format
        dest_fmt = dest_formats[0]
        LOG.debug(
            "Converting image '%s' (%s) into '%s'", self.identifier, fmt, dest_fmt
        )
        converted_location = "%s.%s" % (self.location, dest_fmt)
        if not self.verified or not os.path.exists(converted_location):
            with tempfile.NamedTemporaryFile(mode="w+b") as f:
                block = disk.read(8192)
                while block:
                    f.write(block)
                    f.flush()
                    block = disk.read(8192)
                # call qemu
                cmd = [
                    "qemu-img",
                    "convert",
                    "-f",
                    fmt,
                    "-O",
                    dest_fmt,
                    f.name,
                    converted_location,
                ]
                try:
                    subprocess.run(cmd, capture_output=True, check=True)
                except subprocess.CalledProcessError as e:
                    LOG.error("Could not convert image: %s", e)
                    raise exception.ImageConversionerror(
                        code=e.returncode, reason=e.stderr
                    )
        else:
            LOG.info("Found converted image for '%s' -  noop", self.identifier)
        self.locations.append(converted_location)
        LOG.info(
            "Image '%s' converted and stored at %s", self.identifier, converted_location
        )
        return dest_fmt, open(converted_location, mode)


class HepixImage(BaseImage):
    field_map = {
        "ad:group": "group",
        "ad:mpuri": "mpuri",
        "ad:user:fullname": "user_fullname",
        "ad:user:guid": "user_guid",
        "ad:user:uri": "user_uri",
        "dc:description": "description",
        "dc:identifier": "identifier",
        "dc:title": "title",
        "hv:hypervisor": "hypervisor",
        "hv:format": "format",
        "hv:size": "size",
        "hv:uri": "uri",
        "hv:version": "version",
        "sl:arch": "arch",
        "sl:checksum:sha512": "sha512",
        "sl:comments": "comments",
        "sl:os": "os",
        "sl:osname": "osname",
        "sl:osversion": "osversion",
    }
    required_fields = field_map.keys()

    def __init__(self, image_info):
        super(HepixImage, self).__init__(image_info)

        image_dict = image_info.get("hv:image", {})

        utils.ensure_ca_bundle(
            CONF.download_ca_file, [requests.certs.where()], CONF.ca_path
        )

        for i in self.required_fields:
            value = image_dict.get(i, None)
            if value is None:
                reason = "Invalid image definition, missing '%s'" % i
                raise exception.InvalidImageList(reason=reason)

            attr = self.field_map.get(i)
            setattr(self, attr, value)
        # add everything from hepix as 'extra', so it can be queried in glance
        self.appliance_attributes = image_dict
        # set year 2K as the past
        self.expires = dateutil.parser.parse(
            image_dict.get("dc:date:expires", "2000-01-01 00:00")
        )
        self.expired = self._check_expiry()

    def _check_expiry(self):
        now = datetime.datetime.now(dateutil.tz.tzlocal())
        if self.expires < now:
            LOG.warning("Image '%s' expired on '%s'", self.identifier, self.expires)
            return True
        return False

    def _download(self, location):
        LOG.info(
            "Downloading image '%s' from '%s' into '%s'",
            self.identifier,
            self.uri,
            location,
        )
        with open(location, "wb") as f:
            try:
                response = requests.get(
                    self.uri, stream=True, verify=CONF.download_ca_file
                )
            except Exception as e:
                LOG.error(e)
                raise exception.ImageDownloadFailed(code=e.errno, reason=e)

            if not response.ok:
                LOG.error(
                    "Cannot download image: (%s) %s",
                    response.status_code,
                    response.reason,
                )
                raise exception.ImageDownloadFailed(
                    code=response.status_code, reason=response.reason
                )

            for block in response.iter_content(1024):
                if block:
                    f.write(block)
                    f.flush()
        try:
            self.verify_checksum(location=location)
        except exception.ImageVerificationFailed as e:
            LOG.error(e)
            raise
        else:
            LOG.info("Image '%s' stored as '%s'", self.identifier, location)

    def download(self, basedir):
        if self.expired:
            raise exception.ImageExpired(reason=self.expires)

        # The image has been already downloaded in this execution.
        if self.location is not None:
            raise exception.ImageAlreadyDownloaded(location=self.location)

        location = os.path.join(basedir, self.identifier)

        if not os.path.exists(location):
            self._download(location)
        else:
            # Image exists, is it checksum valid?
            try:
                self.verify_checksum(location=location)
            except exception.ImageVerificationFailed:
                LOG.warning(
                    "Image '%s' present in '%s' is not valid, " "downloading again",
                    self.identifier,
                    location,
                )
                self._download(location)

        self.location = location
        self.locations = [location]
