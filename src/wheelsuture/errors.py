"""Typed, bounded diagnostics. Unsupported does not mean unsafe or corrupt."""


class WheelSutureError(Exception):
    exit_code = 70

    def __init__(
        self,
        message,
        *,
        code="internal_error",
        wheel_id=None,
        operation_id=None,
        path=None,
    ):
        super().__init__(message)
        self.message = str(message)
        self.code = code
        self.wheel_id = wheel_id
        self.operation_id = operation_id
        self.path = path

    def diagnostic(self):
        return dict(
            code=self.code,
            message=self.message[:4096],
            wheel_id=self.wheel_id,
            operation_id=self.operation_id,
            path=self.path,
        )


class InvalidInput(WheelSutureError):
    exit_code = 2

    def __init__(self, message, **kw):
        super().__init__(message, **({"code": "invalid_input"} | kw))


class UnsupportedInput(WheelSutureError):
    exit_code = 3

    def __init__(self, message, **kw):
        super().__init__(message, **({"code": "unsupported_input"} | kw))


class LimitExceeded(UnsupportedInput):
    def __init__(self, message, **kw):
        super().__init__(message, **({"code": "resource_limit"} | kw))


class InputChanged(UnsupportedInput):
    def __init__(self, message, **kw):
        super().__init__(message, **({"code": "input_changed"} | kw))


class OutputError(WheelSutureError):
    exit_code = 4

    def __init__(self, message, *, partial_outputs=(), **kw):
        super().__init__(message, **({"code": "output_error"} | kw))
        self.partial_outputs = tuple(partial_outputs)


class InputIOError(WheelSutureError):
    exit_code = 4

    def __init__(self, message, **kw):
        super().__init__(message, **({"code": "input_io"} | kw))


class VerificationError(WheelSutureError):
    exit_code = 5

    def __init__(self, message, **kw):
        super().__init__(message, **({"code": "evidence_mismatch"} | kw))
