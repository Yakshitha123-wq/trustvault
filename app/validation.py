from werkzeug.utils import secure_filename

MAX_BYTES = 5 * 1024 * 1024


class UploadError(ValueError):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _is_pdf(b):
    return b.startswith(b"%PDF-")


def _is_png(b):
    return b.startswith(b"\x89PNG\r\n\x1a\n")


def _is_jpeg(b):
    return b.startswith(b"\xff\xd8\xff")


def _is_text(b):
    if b"\x00" in b:
        return False
    try:
        b.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


# extension -> (mime type WE decide, content check). The client's Content-Type is never used.
ALLOWED = {
    "pdf": ("application/pdf", _is_pdf),
    "png": ("image/png", _is_png),
    "jpg": ("image/jpeg", _is_jpeg),
    "jpeg": ("image/jpeg", _is_jpeg),
    "txt": ("text/plain", _is_text),
}


def validate_upload(filename, data):
    """Return (clean_name, mime). Raise UploadError if anything is wrong."""
    clean = secure_filename(filename or "")
    if not clean or "." not in clean:
        raise UploadError("A file name with an extension is required.")
    ext = clean.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED:
        raise UploadError("This file type is not allowed.")
    if len(data) == 0:
        raise UploadError("The file is empty.")
    if len(data) > MAX_BYTES:
        raise UploadError("The file is larger than 5 MB.", status=413)
    mime, looks_right = ALLOWED[ext]
    if not looks_right(data):
        raise UploadError("The file content does not match its extension.")
    return clean, mime