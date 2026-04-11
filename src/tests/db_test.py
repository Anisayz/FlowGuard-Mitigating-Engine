import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from src.db.database import AsyncSessionLocal
from src.db.crud import insert_alert, get_alerts

data = {
    "source": "ml_engine",
    "verdict": "ANOMALY",
    "action": "log_only",
    "label": "",
    "confidence": 0.7,
    "ml_source": "classifier",
    "ml_source_url": "http://ml-engine.org/",
    "src_ip": "10.0.0.2",
    "src_port": 8080,
    "dst_port": 8080,
    "dst_ip": "10.0.0.1",
    "protocol": 7,
    "start_time_ms": 0,
    "end_time_ms": 22000,
    "anomaly_score": 6.1,
    "anomaly_flagged": True,
}


async def test_db():
    async with AsyncSessionLocal() as db:
        print("inserting alert")
        await insert_alert(db, data)

        print("fetching alerts")
        alerts = await get_alerts(db)

        print("alerts:", alerts)

    print("done")


if __name__ == "__main__":
    asyncio.run(test_db())