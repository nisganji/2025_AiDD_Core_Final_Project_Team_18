from typing import List, Tuple, Dict

from sqlalchemy import text


def get_distinct_locations_published(db) -> List[str]:
    rows = db.session.execute(
        text(
            """
            SELECT DISTINCT location FROM resources
            WHERE location IS NOT NULL AND TRIM(location)<>'' AND status='published'
            ORDER BY location
            """
        )
    ).all()
    return [r[0] for r in rows]


def get_category_counts_published(db) -> List[Tuple[str, int]]:
    rows = db.session.execute(
        text(
            """
            SELECT category, COUNT(*) as count
            FROM resources
            WHERE status='published' AND category IS NOT NULL AND TRIM(category)<>''
            GROUP BY category
            ORDER BY category
            """
        )
    ).all()
    # returns list of (category, count)
    return [(r[0], r[1]) for r in rows]


def get_booking_trend_counts(db, start_date, end_date) -> List[Tuple[str, int]]:
    rows = db.session.execute(
        text(
            """
            SELECT strftime('%Y-%m-%d', created_at) as day, COUNT(*) as count
            FROM bookings
            WHERE date(created_at) BETWEEN :start AND :end
            GROUP BY day
            ORDER BY day
            """
        ),
        {"start": start_date.strftime('%Y-%m-%d'), "end": end_date.strftime('%Y-%m-%d')},
    ).all()
    return [(d, c) for d, c in rows]


def get_inbox_threads(db, user_id: int) -> List[Tuple[int, int]]:
    rows = db.session.execute(
        text(
            """
            SELECT CASE WHEN sender_id=:uid THEN receiver_id ELSE sender_id END AS other_id, COUNT(*) as cnt
            FROM messages WHERE sender_id=:uid OR receiver_id=:uid GROUP BY other_id
            """
        ),
        {"uid": user_id},
    ).all()
    # returns list of (other_id, count)
    return [(r[0], r[1]) for r in rows]


def get_hourly_bookings(db, day) -> Dict[str, int]:
    rows = db.session.execute(
        text(
            """
            SELECT strftime('%H', start_datetime) as hour, COUNT(*) as count
            FROM bookings
            WHERE date(start_datetime) = :day
            GROUP BY hour
            ORDER BY hour
            """
        ),
        {"day": day.strftime('%Y-%m-%d')},
    ).all()
    return {h: c for h, c in rows}

