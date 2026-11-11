from django.core.management.base import BaseCommand

from api.models import APIPlan

PLANS = [
    dict(slug="free", name="Free", monthly_quota=1000, rate_limit_per_minute=10, price_inr=0),
    dict(slug="starter", name="Starter", monthly_quota=25000, rate_limit_per_minute=60, price_inr=999),
    dict(
        slug="business", name="Business", monthly_quota=250000, rate_limit_per_minute=300,
        price_inr=7999, allow_pay_as_you_go=True, overage_price_inr="0.05",
    ),
]


class Command(BaseCommand):
    help = "Create or update the default API plans (placeholder prices)."

    def handle(self, *args, **options):
        for p in PLANS:
            slug = p.pop("slug")
            obj, created = APIPlan.objects.update_or_create(slug=slug, defaults=p)
            self.stdout.write(f"{'created' if created else 'updated'}: {obj}")