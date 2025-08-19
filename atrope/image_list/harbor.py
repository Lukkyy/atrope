# -*- coding: utf-8 -*-

# (Include Apache License Header Here)

import re
import subprocess
from urllib.parse import quote_plus, urljoin, urlparse

import oras.provider
import requests
from oslo_config import cfg
from oslo_log import log

from atrope import exception, image, utils
from atrope.image_list import source

LOG = log.getLogger(__name__)
CONF = cfg.CONF

# Add any Harbor specific config options if needed via CONF.register_opts


class HarborImageListSource(source.BaseImageListSource):
    """An image list source fetching metadata via Harbor API, downloading via oras."""

    def __init__(
        self,
        name,
        api_url="",  # https://harbor.example.com/api/v2.0
        registry_host="",  # harbor.example.com
        enabled=True,
        subscribed_images=[],
        prefix="",
        project="",
        tag_pattern=None,
        auth_user=None,
        auth_password=None,
        verify_ssl=True,
        page_size=50,
        sharing_model="private",
        **kwargs,
    ):
        super().__init__(
            name,
            url=f"{api_url}/projects/{project}/repositories",
            enabled=enabled,
            subscribed_images=subscribed_images,
            prefix=prefix,
            project=project,
            **kwargs,
        )
        self.api_url = api_url.rstrip("/")
        self.registry_host = registry_host or urlparse(api_url)[1]
        self.tag_pattern_re = re.compile(tag_pattern) if tag_pattern else None
        self.auth_user = auth_user
        self.auth_password = auth_password
        self.verify_ssl = verify_ssl
        self.page_size = page_size
        self.image_list = []
        self._session = None
        self._oras_registry = None
        self.endorser = kwargs.get("endorser", {})
        self.token = kwargs.get("token", "")
        self.sharing_model = sharing_model

        # Harbor images are trusted by default, do not expire and do not need verification
        # We may want to change this by adding some metadata in the harbor project
        self.trusted = True
        self.verified = True
        self.expired = False

        if not self.registry_host:
            raise ValueError(f"registry_host must be provided for Harbor source {name}")

    def _get_session(self):
        """Initialize requests session with authentication."""
        if self._session is None:
            self._session = requests.Session()
            if self.auth_user and self.auth_password:
                self._session.auth = (self.auth_user, self.auth_password)
            elif self.token:
                self._session.headers.update({"Authorization": self.token})
            else:
                LOG.warning(
                    f"No authentication configured for Harbor source {self.name}"
                )
            self._session.verify = self.verify_ssl
            if not self.verify_ssl:
                requests.packages.urllib3.disable_warnings(
                    requests.packages.urllib3.exceptions.InsecureRequestWarning
                )

        return self._session

    def _get_oras_registry(self):
        if self._oras_registry is None:
            try:
                self._oras_registry = oras.provider.Registry(
                    self.registry_host, auth_backend="basic", tls_verify=self.verify_ssl
                )
                self._oras_registry.login(
                    username=self.auth_user,
                    password=self.auth_password,
                    tls_verify=self.verify_ssl,
                )
            except FileNotFoundError:
                raise exception.AtropeException(
                    message="oras command not found. Please ensure oras CLI is installed and in PATH."
                )
            except subprocess.CalledProcessError as e:
                raise exception.AtropeException(
                    message=f"oras login failed: {e.stderr}",
                )
        return self._oras_registry

    def get_manifest(self, image_ref):
        """Helper specifically for running oras pull command."""
        registry = self._get_oras_registry()
        return registry.get_manifest(f"{self.registry_host}/{image_ref}")

    def _fetch_paginated_data(self, url, params=None):
        """Helper to fetch data from a paginated Harbor API endpoint."""
        session = self._get_session()
        results = []
        page = 1
        current_url = url

        while current_url:
            current_params = params.copy() if params else {}
            current_params["page"] = page
            current_params["page_size"] = self.page_size

            try:
                LOG.debug(
                    f"Fetching page {page} from {current_url} with params {current_params}"
                )
                if not urlparse(current_url)[0]:
                    current_url = urljoin(self.api_url, current_url)
                response = session.get(current_url, params=current_params)
                response.raise_for_status()
                data = response.json()
                if not data:
                    LOG.debug(f"No more data found for {current_url} on page {page}.")
                    break
                results.extend(data)

                link_header = response.headers.get("Link")
                next_url = None
                if link_header:
                    links = requests.utils.parse_header_links(link_header)
                    for link in links:
                        if link.get("rel") == "next":
                            next_url = link.get("url")
                            LOG.debug(f"Found next page link: {next_url}")
                            break
                current_url = next_url
                page += 1

            except requests.exceptions.RequestException as e:
                status_code = e.response.status_code if e.response else 0
                msg = f"Harbor API request failed for {self.name} accessing {current_url}: {e}"
                LOG.error(msg)
                self.error = exception.ImageListDownloadFailed(
                    code=status_code, reason=msg
                )
                return None

        return results

    def _list_repositories_in_project(self):
        """Lists repositories within the configured project."""
        repos_url = f"{self.api_url}/projects/{self.project}/repositories"
        LOG.debug(f"Listing repositories from: {repos_url}")
        repositories = self._fetch_paginated_data(repos_url)

        if repositories is None:
            LOG.error(
                f"Failed to list repositories for project {self.project}. See previous errors."
            )
            return None
        if not repositories:
            LOG.warning(
                f"No repositories found in project '{self.project}' for source '{self.name}'."
            )
            return []

        LOG.info(f"Found {len(repositories)} repositories in project '{self.project}'.")
        return repositories

    def _process_artifact(self, artifact, repo_name):
        """Processes a single artifact dictionary, checking tags and filters."""
        if not artifact.get("tags"):
            LOG.debug(
                f"Artifact {artifact.get('digest')} in repo {repo_name} has no tags, skipping."
            )
            return

        matching_tag = None
        for tag_info in artifact.get("tags", []):
            tag_name = tag_info.get("name")
            if not tag_name:
                continue

            process_this_tag = False
            if self.subscribed_images:
                if (
                    tag_name in self.subscribed_images
                    or artifact.get("digest") in self.subscribed_images
                ):
                    process_this_tag = True
            elif self.tag_pattern_re:
                if self.tag_pattern_re.match(tag_name):
                    process_this_tag = True
            elif not self.subscribed_images and not self.tag_pattern_re:
                process_this_tag = True
            if process_this_tag:
                matching_tag = tag_name
                break
        if matching_tag:
            try:
                image_ref = f"{repo_name}:{matching_tag}"
                annotations = artifact.get("extra_attrs", {}).get("annotations", {})
                # update annotations with the ones in the manifest
                manifest = self.get_manifest(image_ref)
                # we are assuming here a single layer, this may not be true
                annotations.update(
                    manifest.get("layers", [{}])[0].get("annotations", {})
                )
                image_digest = manifest.get("layers", [{}])[0].get("digest")
                digest = artifact.get("digest", "")
                if not annotations and "annotations" in artifact:
                    annotations = artifact.get("annotations", {})

                if not annotations:
                    LOG.warning(
                        f"No annotations found for {image_ref} in API list response."
                    )

                if "eu.egi.cloud.tag" not in annotations:
                    LOG.warning(
                        f"No 'eu.egi.cloud.tag' annotation found for {image_ref}, ignoring."
                    )
                    return

                img = image.HarborImage(
                    image_ref,
                    self.registry_host,
                    self.auth_user,
                    self.auth_password,
                    annotations,
                    self.name,
                    digest,
                    image_digest,
                )
                self.image_list.append(img)
                LOG.debug(f"Added Harbor image from API: {image_ref}")

            except Exception as e:
                LOG.error(
                    f"Failed to process artifact tag {repo_name}:{tag_name}: {e}",
                    exc_info=True,
                )

    def _process_repository(self, repo_info):
        """Fetches and processes artifacts for a given repository."""
        repo_name = repo_info.get("name")
        if "/" in repo_name:
            repo_name_only = repo_name.split("/", 1)[1]
        else:
            repo_name_only = repo_name

        if not repo_name_only:
            LOG.warning(
                f"Could not extract repository name from '{repo_name}', skipping."
            )
            return

        encoded_repo_name = quote_plus(repo_name_only)
        artifacts_url = f"{self.api_url}/projects/{self.project}/repositories/{encoded_repo_name}/artifacts"
        LOG.debug(
            f"Listing artifacts for repository '{repo_name}' from {artifacts_url}"
        )

        artifacts = self._fetch_paginated_data(
            artifacts_url,
            params={
                "with_tag": "true",
                "with_scan_overview": "false",
                "with_label": "false",
                "with_accessory": "true",
            },
        )

        if artifacts is None:
            LOG.error(
                f"Failed to list artifacts for repository '{repo_name}'. Skipping this repository."
            )
            return

        if not artifacts:
            LOG.debug(f"No artifacts found in repository '{repo_name}'.")
            return

        LOG.debug(f"Processing {len(artifacts)} artifacts for repository '{repo_name}'")
        for artifact in artifacts:
            self._process_artifact(artifact, repo_name)

    @source._set_error
    def fetch(self):
        if not self.enabled:
            LOG.info(f"Harbor source '{self.name}' disabled, skipping fetch.")
            return
        if not self.api_url or not self.project:
            LOG.info(f"Harbor source '{self.name}' config incomplete, skipping fetch.")
            return

        LOG.info(
            f"Fetching images via Harbor API for project: {self.name} ({self.project})"
        )
        self.image_list = []
        self.error = None

        repositories = self._list_repositories_in_project()
        if not repositories:
            return

        for repo_info in repositories:
            self._process_repository(repo_info)

        LOG.info(
            f"Finished fetching Harbor source '{self.name}'. Found {len(self.image_list)} "
            f"matching images across all repositories in project '{self.project}'."
        )

    def print_list(self, contents=False):
        d = {
            "name": self.name,
            "url": self.url,
            "enabled": self.enabled,
            "project": self.project,
            "registry_host": self.registry_host,
            "endorser": self.endorser,
        }

        if self.error is not None:
            d["error"] = str(self.error)

        try:
            images = [str(img.identifier) for img in (self.image_list or [])]
        except exception.ImageListNotFetched:
            images = None

        d["images found"] = images if images else "None"

        subscribed_cfg = (
            self.subscribed_images if self.subscribed_images else "All (or by pattern)"
        )
        d["images (subscribed config)"] = subscribed_cfg
        if self.tag_pattern_re:
            d["tag_pattern"] = self.tag_pattern_re.pattern

        utils.print_dict(d)

    def get_subscribed_images(self):
        """Get the subscribed images from the fetched image list."""
        if not self.enabled:
            return []

        if self.image_list is None:
            LOG.error(f"Image list {self.name} has not been fetched!")
            return []

        if not self.subscribed_images:
            return self.image_list
        else:
            return [
                img
                for img in self.image_list
                if img.identifier in self.subscribed_images
            ]

    def get_valid_subscribed_images(self):
        return [i for i in self.get_subscribed_images() if i.verified and not i.expired]

    def get_images(self):
        """Get the images defined in the fetched image list."""
        if not self.enabled:
            return []

        if self.image_list is None:
            raise exception.ImageListNotFetched(id=self.name)

        return self.image_list
