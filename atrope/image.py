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


class HarborImage(BaseImage):
    """Represents an image fetched via Harbor API, downloaded via oras."""

    def __init__(self, image_ref, annotations, list_name, digest):
        """
        Initialize HarborImage.

        :param image_ref: Full image reference (e.g., registry/repo:tag) from API
        :param annotations: Parsed OCI annotations dictionary from API response.
        :param list_name: Name of the source list this image belongs to.
        :param digest: SHA256 identifier of the image.
        """
        super(HarborImage, self).__init__(annotations)

        self.image_ref = image_ref
        self.list_name = list_name
        self.annotations = annotations if annotations else {}
        self.digest = digest  # SHA256 identifier of the image

        self.identifier = f"{image_ref}-{digest}"

        self.format = self.annotations.get("org.openstack.glance.disk_format", "raw")
        self.container_format = self.annotations.get("org.openstack.glance.container_format", "bare")

        self.sha512 = None

        self.revision = self.annotations.get("org.opencontainers.image.revision")
        self.source_url = self.annotations.get("org.opencontainers.image.source")
        self.appliance_attributes = self.annotations

        self.uri = image_ref
        self.location = None
        self.locations = []
        self.verified = False
        self.expired = False

        LOG.debug(f"HarborImage initialized: {self.identifier}, format={self.format}")

    def _run_oras_pull(self, command_list):
        """Helper specifically for running oras pull command."""
        try:
            LOG.debug(f"Running oras command: {' '.join(command_list)}")
            result = subprocess.run(
                command_list,
                capture_output=True,
                text=True,
                check=True,
                encoding='utf-8'
            )
            LOG.debug(f"Oras pull successful. Stdout: {result.stdout[:200]}...")
            print(result.stdout)
            return result.stdout
        except FileNotFoundError:
            raise exception.AtropeException(message="oras command not found. Please ensure oras CLI is installed and in PATH.")
        except subprocess.CalledProcessError as e:
            raise exception.ImageDownloadFailed(code=e.returncode, reason=f"oras pull failed for {self.image_ref}: {e.stderr}")
        except Exception as e:
            raise exception.AtropeException(message=f"An unexpected error occurred running oras pull for {self.image_ref}: {e}")

    def download(self, basedir):
        """Download the image using oras pull."""
        if self.expired:
            raise exception.ImageExpired(reason="Image marked as expired")

        if self.location and os.path.exists(self.location):
            try:
                self.verify_checksum()
                LOG.info(f"Image {self.identifier} already downloaded and verified at {self.location}")
                raise exception.ImageAlreadyDownloaded(location=self.location)
            except exception.ImageVerificationFailed:
                LOG.warning(f"Cached image {self.identifier} failed verification. Re-downloading.")
                utils.rm(self.location)
                self.location = None; self.locations = []; self.verified = False; self.sha512 = None

        with tempfile.TemporaryDirectory(suffix=f"-{self.list_name}") as tmpdir:
            LOG.info(f"Downloading Harbor image {self.identifier} ({self.image_ref}) using oras to {tmpdir}")
            pull_cmd = ["oras", "pull", "--insecure", "--allow-path-traversal", self.image_ref, "-o", tmpdir]

            try:
                self._run_oras_pull(pull_cmd)
            except exception.ImageDownloadFailed as e:
                LOG.error(f"Failed to download {self.identifier} using oras: {e}")
                raise

            print(f"Pulled image TTTTOOOO {tmpdir}")

            pulled_files = os.listdir(tmpdir)
            if not pulled_files:
                raise exception.ImageDownloadFailed(code=1, reason=f"oras pull to {tmpdir} resulted in no files for {self.identifier}.")
            image_filename = max(pulled_files, key=lambda f: os.path.getsize(os.path.join(tmpdir, f)) if os.path.isfile(os.path.join(tmpdir, f)) else -1)
            if not image_filename or not os.path.isfile(os.path.join(tmpdir, image_filename)):
                raise exception.ImageDownloadFailed(code=1, reason=f"Could not identify main image file in oras pull output for {self.identifier} in {tmpdir}")

            pulled_image_path = os.path.join(tmpdir, image_filename)
            LOG.debug(f"Identified pulled image file: {pulled_image_path}")

            safe_filename = "".join(c if c.isalnum() or c in ('-', '_', '.') else '_' for c in self.identifier.replace('/', '_').replace(':', '_'))
            final_location = os.path.join(basedir, safe_filename)
            utils.makedirs(basedir)

            try:
                os.rename(pulled_image_path, final_location)
                self.location = final_location
                self.locations = [final_location]
                LOG.info(f"Stored Harbor image {self.identifier} at {self.location}")
            except OSError as e:
                raise exception.AtropeException(f"Failed to move downloaded file to cache for {self.identifier}: {e}")

        try:
            checksum_obj = utils.get_file_checksum(self.location)
            self.sha512 = checksum_obj.hexdigest()
            LOG.info(f"Calculated SHA512 for {self.identifier}: {self.sha512}")
            self.verify_checksum()
        except FileNotFoundError:
            raise exception.ImageNotFoundOnDisk(location=self.location)
        except exception.ImageVerificationFailed as e:
            LOG.error(f"Immediate verification failed for {self.identifier}: {e}")
            utils.rm(self.location)  # Clean up failed download
            self.location = None
            self.locations = []
            self.verified = False
            self.sha512 = None
            raise
        except Exception as e:
            LOG.error(f"Failed to calculate or verify checksum for {self.identifier}: {e}")
            utils.rm(self.location)  # Clean up failed download
            self.location = None
            self.locations = []
            self.verified = False
            self.sha512 = None
            raise exception.ImageVerificationFailed(id=self.identifier, expected="N/A", obtained=f"Error during checksum: {e}")

    def verify_checksum(self, location=None):
        """Verify the image's calculated SHA512 checksum."""
        # TODO check Harbor digest and verify based on it
        pass
