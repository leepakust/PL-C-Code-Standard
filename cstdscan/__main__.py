"""Allow `python -m cstdscan <path>` as well as `python scan_c_code.py`."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scan_c_code import main                            # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
