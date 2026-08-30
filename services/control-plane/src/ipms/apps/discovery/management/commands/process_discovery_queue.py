from django.core.management.base import BaseCommand

from ipms.apps.discovery.services import process_discovery_queue


class Command(BaseCommand):
    help = "Process queued connector discovery jobs for the isolated worker service."

    def add_arguments(self, parser) -> None:
        parser.add_argument("--limit", type=int, default=5)

    def handle(self, *args, **options) -> None:
        limit = options["limit"]
        if limit < 1 or limit > 100:
            raise ValueError("The queue processing limit must be between 1 and 100.")
        processed = process_discovery_queue(limit=limit)
        self.stdout.write(f"Processed {processed} discovery job(s).")
