import json

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from detectors.exceptions import DetectorError
from scans.serializers import ScanSerializer
from scans.services import run_scan


class Command(BaseCommand):
    help = "Run one scan from the terminal: try_scan phishing_url 'https://example.com'"

    def add_arguments(self, parser):
        parser.add_argument("module")
        parser.add_argument("value")
        parser.add_argument("--field", default="url")
        parser.add_argument("--username")

    def handle(self, *args, **opts):
        User = get_user_model()
        qs = User.objects.filter(username=opts["username"]) if opts["username"] else User.objects.filter(is_superuser=True)
        user = qs.first()
        if user is None:
            raise CommandError("No matching user found.")
        try:
            scan = run_scan(user=user, module=opts["module"], payload={opts["field"]: opts["value"]})
        except DetectorError as exc:
            raise CommandError(str(exc))
        self.stdout.write(json.dumps(ScanSerializer(scan).data, indent=2, default=str))