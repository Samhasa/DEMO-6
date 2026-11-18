import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from alert_utils import get_alerts_by_source


def main():
    payload = "' OR 1=1 --"
    with tempfile.TemporaryDirectory() as directory:
        db_path = Path(directory) / "alerts.db"
        with closing(sqlite3.connect(db_path)) as conn:
            conn.execute("CREATE TABLE alerts (source TEXT)")
            conn.executemany(
                "INSERT INTO alerts (source) VALUES (?)",
                [("api-gateway",), ("other-service",), (payload,), ("O'Reilly",)],
            )
            conn.commit()

        normal_results = get_alerts_by_source(db_path, "api-gateway")
        assert normal_results == [("api-gateway",)], normal_results

        injection_results = get_alerts_by_source(db_path, payload)
        assert injection_results == [(payload,)], f"Injection returned: {injection_results!r}"

        quoted_results = get_alerts_by_source(db_path, "O'Reilly")
        assert quoted_results == [("O'Reilly",)], quoted_results

    print("SQL injection check passed: inputs are treated as literal values.")


if __name__ == "__main__":
    main()