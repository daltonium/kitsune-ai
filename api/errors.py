from rest_framework import exceptions, status
from rest_framework.views import exception_handler

FALLBACK_CODES = {
    404: "not_found",
    405: "method_not_allowed",
    415: "unsupported_media_type",
}


class InvalidInput(exceptions.APIException):
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = "Invalid input."
    default_code = "invalid_input"


class PayloadTooLarge(exceptions.APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = "Request body is too large."
    default_code = "payload_too_large"


class ModuleUnavailable(exceptions.APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = "This detection module is not available yet."
    default_code = "module_unavailable"


class CompanyAlreadyRegistered(exceptions.APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "This account already has a company."
    default_code = "company_already_registered"


class KeyLimitReached(exceptions.APIException):
    status_code = status.HTTP_409_CONFLICT
    default_detail = "Active API key limit reached. Revoke a key first."
    default_code = "key_limit_reached"


def api_exception_handler(exc, context):
    """DRF's handler, with the body reshaped to the web error format."""
    response = exception_handler(exc, context)
    if response is None:
        return None

    if isinstance(exc, exceptions.ValidationError):
        response.data = {
            "error": {
                "code": "validation_error",
                "message": "Invalid input.",
                "fields": response.data,
            }
        }
        return response

    codes = (
        exc.get_codes()
        if isinstance(exc, exceptions.APIException)
        else None
    )
    code = (
        codes
        if isinstance(codes, str)
        else FALLBACK_CODES.get(response.status_code, "error")
    )
    detail = getattr(exc, "detail", None)
    message = (
        str(detail)
        if isinstance(detail, str)
        else "The request could not be processed."
    )
    response.data = {"error": {"code": code, "message": message}}
    return response