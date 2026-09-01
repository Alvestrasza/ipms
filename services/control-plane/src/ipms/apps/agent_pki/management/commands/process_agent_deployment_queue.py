from django.core.management.base import BaseCommand

from ipms.apps.agent_pki.deployment import process_deployment_queue


class Command(BaseCommand):
    help = "Process queued fixed Windows Agent deployment jobs."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=2)

    def handle(self, *args, **options):
        limit = options["limit"]
        if not 1 <= limit <= 10:
            raise ValueError("The deployment processing limit must be between 1 and 10.")
        processed = process_deployment_queue(limit=limit)
        self.stdout.write(f"Processed {processed} Windows Agent deployment job(s).")
