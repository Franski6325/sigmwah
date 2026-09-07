"""Sigmwah-specific exceptions."""


class SigmwahError(Exception):
    """Base error for Sigmwah."""


class MappingError(SigmwahError):
    """Invalid or unreadable mapping YAML."""


class IdRangeExhaustedError(SigmwahError):
    """No remaining Wazuh rule IDs in the configured range."""


class ValidationError(SigmwahError):
    """XML or Wazuh smoke-test validation failed."""


class DownloadError(SigmwahError):
    """SigmaHQ download failed."""


class UnsupportedConversionError(SigmwahError):
    """A Sigma construct cannot be expressed in the Wazuh target."""
