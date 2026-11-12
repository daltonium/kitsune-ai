import json

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from detectors.exceptions import DetectorError
from scans.serializers import ScanSerializer
from scans.services import run_scan


class Command(BaseCommand):
    help = (
        "Run one scan from the terminal.\n"
        "  try_scan phishing_url 'https://example.com'\n"
        "  try_scan network_intrusion --file sample_flows.csv\n"
        "  try_scan phishing_email --set \"subject=Hi\" --set \"body=Some email text here\""
    )

    def add_arguments(self, parser):
        parser.add_argument("module")
        parser.add_argument("value", nargs="?")
        parser.add_argument("--field", default="url")
        parser.add_argument("--json", dest="json_payload", help="Full JSON payload")
        parser.add_argument("--file", help="Path of a file to upload as 'file'")
        parser.add_argument("--set", dest="set_pairs", action="append", help="key=value (repeatable)")
        parser.add_argument("--username")

    def handle(self, *args, **opts):
        User = get_user_model()
        qs = User.objects.filter(username=opts["username"]) if opts["username"] else User.objects.filter(is_superuser=True)
        user = qs.first()
        if user is None:
            raise CommandError("No matching user found.")
        handle_obj = None
        try:
            if opts["json_payload"]:
                try:
                    payload = json.loads(opts["json_payload"])
                except json.JSONDecodeError as exc:
                    raise CommandError(f"Invalid JSON: {exc}")
            elif opts["file"]:
                try:
                    handle_obj = open(opts["file"], "rb")
                except OSError as exc:
                    raise CommandError(f"Cannot open file: {exc}")
                payload = {"file": handle_obj}
            elif opts["set_pairs"]:
                payload = {}
                for pair in opts["set_pairs"]:
                    key, sep, val = pair.partition("=")
                    if not sep or not key:
                        raise CommandError("--set expects key=value")
                    payload[key] = val
            elif opts["value"] is not None:
                payload = {opts["field"]: opts["value"]}
            else:
                raise CommandError("Provide a value, --set, --json or --file.")
            try:
                scan = run_scan(user=user, module=opts["module"], payload=payload)
            except DetectorError as exc:
                raise CommandError(str(exc))
        finally:
            if handle_obj:
                handle_obj.close()
        self.stdout.write(json.dumps(ScanSerializer(scan).data, indent=2, default=str))