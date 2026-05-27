"""
test_vn_recognizers.py
Chạy: python3 test_vn_recognizers.py
"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from dlp.dlp_engine import DLPEngine

engine = DLPEngine()

TEST_CASES = [
    # (mô tả, text đầu vào, entity mong đợi)
    ("CCCD 12 số",          "CCCD của tôi là 079204123456",              "VN_CCCD"),
    ("CMND 9 số",           "CMND số 027084123",                          "VN_CCCD"),
    ("SĐT Viettel",         "liên hệ số điện thoại 0912345678",           "VN_PHONE"),
    ("SĐT có +84",          "phone: +84 912 345 678",                     "VN_PHONE"),
    ("MST doanh nghiệp",    "mã số thuế công ty: 0123456789",             "VN_TAX_CODE"),
    ("MST chi nhánh",       "mst chi nhánh: 0123456789-001",              "VN_TAX_CODE"),
    ("Hộ chiếu mới",        "passport number B12345678",                  "VN_PASSPORT"),
    ("Hộ chiếu cũ",         "số hộ chiếu: A1234567",                      "VN_PASSPORT"),
    ("STK ngân hàng",       "số tài khoản vietcombank: 1234567890123",    "VN_BANK_ACCOUNT"),
    ("Biển số ô tô",        "biển số xe 51A-123.45",                      "VN_LICENSE_PLATE"),
    ("Biển số xe máy",      "biển số xe máy 59B1-12345",                  "VN_LICENSE_PLATE"),
    ("Thẻ BHYT",            "số thẻ bảo hiểm y tế HS4010123456789",      "VN_BHYT"),
    # Negative cases
    ("Ngày tháng bình thường", "sinh ngày 22/05/2001",                    None),
    ("Số thông thường",        "mã đơn hàng 123456",                      None),
]


async def run_tests():
    print("=" * 60)
    print("TEST BỘ VN RECOGNIZERS")
    print("=" * 60)

    passed = 0
    failed = 0

    for desc, text, expected_entity in TEST_CASES:
        result, stats = await engine.redact(text)
        detected = list(stats["pii_types"].keys())

        if expected_entity is None:
            # Negative case: không được detect VN entity nào
            vn_detected = [e for e in detected if e.startswith("VN_")]
            ok = len(vn_detected) == 0
        else:
            ok = expected_entity in detected

        status = "✅ PASS" if ok else "❌ FAIL"
        if ok:
            passed += 1
        else:
            failed += 1

        print(f"{status} | {desc}")
        print(f"       Input  : {text}")
        print(f"       Result : {result}")
        print(f"       Detect : {detected}")
        if expected_entity:
            print(f"       Expect : {expected_entity}")
        print()

    print("=" * 60)
    print(f"KẾT QUẢ: {passed}/{passed+failed} PASS")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_tests())