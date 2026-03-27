import cv2
import ipaddress
import re
from urllib.parse import parse_qs, urlparse


def _is_qr_present(detector, image):
    """Return True if QR is detected or decoded in the given image."""
    decoded_text, points, _ = detector.detectAndDecode(image)
    if decoded_text:
        return True
    if points is not None and len(points) > 0:
        return True

    # Fallback for frames containing multiple/small QR regions.
    try:
        retval, decoded_info, multi_points, _ = detector.detectAndDecodeMulti(image)
        if retval:
            return True
        if decoded_info and any(decoded_info):
            return True
        if multi_points is not None and len(multi_points) > 0:
            return True
    except Exception:
        # Some OpenCV builds may not expose detectAndDecodeMulti.
        pass

    return False


def _extract_qr_payload(detector, image):
    """Return (detected, payload_text) from a candidate frame."""
    decoded_text, points, _ = detector.detectAndDecode(image)
    if decoded_text:
        return True, decoded_text

    detected = points is not None and len(points) > 0

    # Fallback for frames containing multiple/small QR regions.
    try:
        retval, decoded_info, multi_points, _ = detector.detectAndDecodeMulti(image)
        if decoded_info:
            for item in decoded_info:
                if item:
                    return True, item
        if retval or (multi_points is not None and len(multi_points) > 0):
            detected = True
    except Exception:
        # Some OpenCV builds may not expose detectAndDecodeMulti.
        pass

    return detected, ""


def _iter_candidates(image):
    """Yield several preprocessed variants to improve decode reliability."""
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(gray)
    _, otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    adaptive = cv2.adaptiveThreshold(
        gray,
        255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        31,
        5,
    )
    upscaled = cv2.resize(gray, None, fx=2.0, fy=2.0, interpolation=cv2.INTER_CUBIC)
    return (image, gray, clahe, otsu, adaptive, upscaled)


def analyze_qr_code(image_path):
    """
    Analyze a frame for QR presence and payload.
    Returns: {"detected": bool, "payload": str}
    """
    try:
        image = cv2.imread(image_path)
        if image is None:
            return {"detected": False, "payload": ""}

        detector = cv2.QRCodeDetector()

        detected_any = False
        best_payload = ""

        for candidate in _iter_candidates(image):
            detected, payload = _extract_qr_payload(detector, candidate)
            if detected:
                detected_any = True
            if payload:
                best_payload = payload.strip()
                break

        return {"detected": detected_any, "payload": best_payload}
    except Exception as e:
        print(f"Error analyzing QR code: {e}")
        return {"detected": False, "payload": ""}


def assess_qr_payload(payload):
    """
    Heuristic safety classification for QR payloads.
    Returns: {
            "verdict": "safe" | "malicious" | "undetermined",
      "is_malicious": bool,
      "risk_score": int,
      "reasons": list[str],
      "payload_type": str
    }
    """
    text = (payload or "").strip()
    reasons = []
    risk_score = 0
    payload_type = "text"

    if not text:
        return {
            "verdict": "undetermined",
            "is_malicious": False,
            "risk_score": 0,
            "reasons": ["QR detected but payload could not be decoded clearly."],
            "payload_type": "unknown",
        }

    strong_signals = 0

    if len(text) > 280:
        risk_score += 1
        reasons.append("Very long payload can hide suspicious content.")

    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
        risk_score += 2
        strong_signals += 1
        reasons.append("Payload contains control characters.")

    parsed = urlparse(text)
    has_scheme = bool(parsed.scheme)
    is_url = has_scheme and bool(parsed.netloc)

    if is_url:
        payload_type = "url"
        host = parsed.netloc.rsplit("@", 1)[-1].split(":", 1)[0].lower()

        safe_schemes = {"http", "https", "upi", "mailto", "tel", "sms", "geo", "otpauth"}
        risky_schemes = {"javascript", "data", "file", "vbscript"}

        if parsed.scheme in risky_schemes:
            risk_score += 4
            strong_signals += 1
            reasons.append("High-risk URL scheme detected.")
        elif parsed.scheme not in safe_schemes:
            risk_score += 1
            reasons.append("Uncommon URL scheme detected.")

        if parsed.scheme == "http":
            reasons.append("HTTP link is not encrypted.")

        if "@" in parsed.netloc:
            risk_score += 3
            strong_signals += 1
            reasons.append("URL uses @ in host section.")

        if host.startswith("xn--") or ".xn--" in host:
            risk_score += 2
            strong_signals += 1
            reasons.append("Punycode domain may be impersonating a trusted site.")

        try:
            ipaddress.ip_address(host)
            risk_score += 2
            strong_signals += 1
            reasons.append("URL uses direct IP address instead of domain.")
        except ValueError:
            pass

        if host.count(".") >= 3:
            risk_score += 1
            reasons.append("Domain has many subdomains.")

        shorteners = {
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "goo.gl",
            "is.gd",
            "cutt.ly",
            "rb.gy",
        }
        if host in shorteners:
            risk_score += 1
            reasons.append("Shortened link detected.")

        query_keys = {k.lower() for k in parse_qs(parsed.query).keys()}
        redirect_keys = {"url", "redirect", "redirect_uri", "next", "target", "dest", "destination"}
        if query_keys.intersection(redirect_keys):
            risk_score += 2
            strong_signals += 1
            reasons.append("URL contains redirect-style query parameters.")
    else:
        suspicious_terms = ("login", "verify", "update-password", "wallet", "seed phrase", "otp")
        lowered = text.lower()
        if any(term in lowered for term in suspicious_terms):
            risk_score += 1
            reasons.append("Text payload includes potentially sensitive-action keywords.")

    is_malicious = strong_signals >= 1 and risk_score >= 4
    verdict = "malicious" if is_malicious else "safe"

    if not reasons:
        reasons.append("No high-risk indicators found by current checks.")

    return {
        "verdict": verdict,
        "is_malicious": is_malicious,
        "risk_score": risk_score,
        "reasons": reasons,
        "payload_type": payload_type,
    }


def recognize_qr_code(image_path):
    """
    Tries to recognize a QR code in the given image using OpenCV.
    Returns True if a QR code is detected, False otherwise.
    """
    try:
        return analyze_qr_code(image_path).get("detected", False)
    except Exception as e:
        print(f"Error detecting QR code: {e}")
        return False
