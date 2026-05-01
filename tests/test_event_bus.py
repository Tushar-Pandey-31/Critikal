"""
Tests for src/agent/events.py — EventBus, Event, EventType.
"""

import asyncio
import pytest

from src.agent.events import EventBus, Event, EventType


class TestEvent:

    def test_event_construction(self):
        event = Event(type=EventType.TOOL_START, data={"tool": "bash"})
        assert event.type == EventType.TOOL_START
        assert event.data["tool"] == "bash"
        assert event.timestamp > 0

    def test_event_with_empty_data(self):
        event = Event(type=EventType.STATUS)
        assert event.data == {}

    def test_all_event_types_exist(self):
        types = list(EventType)
        names = [t.value for t in types]
        assert "message_chunk" in names
        assert "tool_start" in names
        assert "tool_complete" in names
        assert "finding_added" in names
        assert "error" in names


class TestEventBus:

    @pytest.mark.asyncio
    async def test_emit_and_receive(self):
        bus = EventBus()
        queue = bus.create_subscriber()

        event = Event(type=EventType.STATUS, data={"message": "hello"})
        await bus.emit(event)

        received = queue.get_nowait()
        assert received.type == EventType.STATUS
        assert received.data["message"] == "hello"

    @pytest.mark.asyncio
    async def test_multiple_subscribers_receive_event(self):
        bus = EventBus()
        q1 = bus.create_subscriber()
        q2 = bus.create_subscriber()

        await bus.emit(Event(type=EventType.FINDING_ADDED, data={"index": 0}))

        e1 = q1.get_nowait()
        e2 = q2.get_nowait()
        assert e1.type == EventType.FINDING_ADDED
        assert e2.type == EventType.FINDING_ADDED

    @pytest.mark.asyncio
    async def test_remove_subscriber(self):
        bus = EventBus()
        q = bus.create_subscriber()
        bus.remove_subscriber(q)

        await bus.emit(Event(type=EventType.STATUS, data={}))
        assert q.empty()  # No events received after removal

    def test_emit_sync(self):
        bus = EventBus()
        q = bus.create_subscriber()

        bus.emit_sync(Event(type=EventType.COMPACT))
        event = q.get_nowait()
        assert event.type == EventType.COMPACT

    @pytest.mark.asyncio
    async def test_multiple_events_in_order(self):
        bus = EventBus()
        q = bus.create_subscriber()

        events = [
            Event(type=EventType.TOOL_START, data={"n": 1}),
            Event(type=EventType.TOOL_COMPLETE, data={"n": 2}),
            Event(type=EventType.TURN_COMPLETE, data={"n": 3}),
        ]
        for e in events:
            await bus.emit(e)

        received = [q.get_nowait() for _ in range(3)]
        assert [r.data["n"] for r in received] == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_no_events_for_late_subscriber(self):
        bus = EventBus()
        await bus.emit(Event(type=EventType.STATUS, data={"msg": "early"}))

        # Subscribe AFTER emission
        q = bus.create_subscriber()
        assert q.empty()  # Didn't see the early event

    @pytest.mark.asyncio
    async def test_subscribe_async_iterator(self):
        bus = EventBus()

        received = []

        async def consumer():
            async for event in bus.subscribe():
                received.append(event)
                if len(received) >= 2:
                    break

        consumer_task = asyncio.create_task(consumer())

        # Small delay to let consumer start
        await asyncio.sleep(0)
        await bus.emit(Event(type=EventType.STATUS, data={"n": 1}))
        await bus.emit(Event(type=EventType.STATUS, data={"n": 2}))

        await asyncio.wait_for(consumer_task, timeout=2.0)
        assert len(received) == 2
        assert received[0].data["n"] == 1
        assert received[1].data["n"] == 2
