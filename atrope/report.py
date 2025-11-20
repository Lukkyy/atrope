# Copyright 2025 Lukas Moder
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

from collections import defaultdict
import os

from atrope import cache, utils
from atrope.dispatcher import glance
from atrope.image_list import harbor

from oslo_config import cfg
from oslo_log import log

CONF = cfg.CONF

LOG = log.getLogger(__name__)


class ReportGenerator(object):
    def __init__(self, manager):
        self.manager = manager
        self.detailed = CONF.command.detailed

    def run_all_reports(self):
        LOG.info("--- Harbor Report ---")
        self.generate_harbor_report()
        LOG.info("\n--- Glance Report ---")
        self.generate_glance_report()
        LOG.info("\n--- Local Cache Report ---")
        self.generate_cache_report()

    def _generate_harbor_report_data(self, lst, report):
        lst.fetch()
        images = lst.get_images()
        report["image_count"] = len(images)

        return images

    def generate_harbor_report(self):
        reports = []
        all_images = []
        for lst in self.manager.lists.values():
            if not isinstance(lst, harbor.HarborImageListSource):
                continue

            report = {
                "source_name": lst.name,
                "image_count": 0,
            }

            images = self._generate_harbor_report_data(lst, report)
            all_images.extend(images)
            reports.append(report)

        if not reports:
            LOG.info("No Harbor sources configured.")
            return

        fields = [
            "source_name",
            "image_count",
        ]
        utils.print_list(reports, fields)

        if self.detailed and all_images:
            LOG.info("\n--- Harbor Image Details ---")
            image_details = []
            for img in all_images:
                image_detail = {
                    "Image Reference": img.image_ref,
                    "Hash": img.hash,
                    "Disk Format": img.format,
                    "Annotations": "\n".join([f"{k}: {v}" for k, v in img.annotations.items()])
                }
                image_details.append(image_detail)
                utils.print_dict(image_detail)

    def generate_glance_report(self):
        report = {
            "image_count": 0,
            "total_size_gb": 0,
            "status_breakdown": "",
        }

        glance_dispatcher = glance.Dispatcher()
        client = glance_dispatcher.client
        images = list(client.image.images(tag=glance.CONF.glance.tag))

        if not images:
            LOG.info("No images managed by atrope found in Glance.")
            return

        report["image_count"] = len(images)
        total_size_bytes = sum(img.size for img in images if img.size)
        report["total_size_gb"] = round(total_size_bytes / (1024**3), 2)

        status_counts = defaultdict(int)
        for img in images:
            status_counts[img.status] += 1
        report["status_breakdown"] = ", ".join([f"{status}: {count}" for status, count in status_counts.items()])

        utils.print_dict(report)

        if self.detailed and images:
            LOG.info("\n--- Glance Image Details ---")
            image_details = []
            for img in images:
                image_details.append({
                    "Name": img.name,
                    "ID": img.id,
                    "Size (GB)": round(img.size / (1024**3), 2) if img.size else 0,
                    "Status": img.status
                })
            utils.print_list(image_details, ["Name", "ID", "Size (GB)", "Status"])

    def generate_cache_report(self):
        cache_manager = cache.CacheManager()
        cache_path = cache_manager.path

        total_size_bytes = 0
        file_count = 0
        if os.path.exists(cache_path):
            for dirpath, dirnames, filenames in os.walk(cache_path):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    if not os.path.islink(fp):
                        total_size_bytes += os.path.getsize(fp)
                        file_count += 1

        report = {
            "cache_path": str(cache_path),
            "total_size_gb": round(total_size_bytes / (1024**3), 2),
            "file_count": file_count
        }
        utils.print_dict(report)
