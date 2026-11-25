#!/usr/bin/env python3
"""Independent hyper-h2 final-response ledger; this is not a throughput test.

Requires h2==4.3.0. Run against the actual candidate binary, not a shared runner.
"""

import argparse
import asyncio
import hashlib
import json
import traceback
from pathlib import Path

import h2.config
import h2.connection
import h2.events


async def check(binary, workers):
    ledgers = []
    peers = set()
    failures = []

    async def peer(reader, writer):
        task = asyncio.current_task()
        peers.add(task)
        conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=False)
        )
        ledger = dict(accepted=0, completed=0, pins=0, after_release=0, ping_ack=False)
        ledgers.append(ledger)
        pinned = []
        timer = None
        released = False
        last = -1

        async def flush():
            writer.write(conn.data_to_send())
            await writer.drain()

        async def release():
            nonlocal released
            await asyncio.sleep(0.5)
            released = True
            # The control and final bytes share a flush. Success must retain
            # both full response validation and the outstanding PING reply.
            conn.ping(b"draining")
            for stream in pinned:
                conn.send_data(stream, b"\n", end_stream=True)
                ledger["completed"] += 1
            ledger["pins"] = 0
            await flush()

        try:
            conn.initiate_connection()
            await flush()
            while data := await reader.read(65536):
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        assert event.stream_id == last + 2
                        last = event.stream_id
                        ledger["accepted"] += 1
                        ledger["after_release"] += int(released)
                        conn.send_headers(
                            event.stream_id,
                            [(":status", "200"), ("content-length", "13")],
                        )
                        if len(pinned) < 2:
                            pinned.append(event.stream_id)
                            ledger["pins"] += 1
                            conn.send_data(event.stream_id, b"hello world!")
                            if timer is None:
                                timer = asyncio.create_task(release())
                        else:
                            conn.send_data(event.stream_id, b"hello world!\n", end_stream=True)
                            ledger["completed"] += 1
                    elif isinstance(event, h2.events.PingAckReceived):
                        assert event.ping_data == b"draining"
                        ledger["ping_ack"] = True
                    elif isinstance(event, h2.events.StreamReset):
                        raise AssertionError(f"unexpected reset: {event}")
                await flush()
            assert released and ledger["pins"] == 0
            assert ledger["accepted"] == ledger["completed"] > 8
            assert ledger["after_release"] == 0 and ledger["ping_ack"]
        except Exception:
            failures.append(traceback.format_exc())
        finally:
            if not released or ledger["pins"] or ledger["accepted"] != ledger["completed"]:
                failures.append(f"incomplete response ledger: {ledger}")
            if timer is not None:
                if not timer.done():
                    timer.cancel()
                result = await asyncio.gather(timer, return_exceptions=True)
                failures.extend(repr(e) for e in result if isinstance(e, Exception))
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                failures.append(traceback.format_exc())
            finally:
                peers.discard(task)

    server = await asyncio.start_server(peer, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    command = [
        str(binary), "--http2", "-z", "200ms", "--drain-timeout", "2s",
        "-c", "4", "-t", str(workers), "-p", "8", "--batch-linger", "1", "-j",
        f"http://127.0.0.1:{port}/",
    ]
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == 0, stderr.decode()
        server.close()
        await server.wait_closed()
        if peers:
            await asyncio.wait_for(asyncio.gather(*peers), 5)
        assert not failures, failures
        assert len(ledgers) == 4, ledgers
        report = json.loads(stdout)
        total = sum(row["accepted"] for row in ledgers)
        assert report["requests"] == dict(total=total, ok=total, errors=0, connectErrors=0)
        assert report["latencySamples"] == total
        assert report["statusCodes"] == {"200": total}
        assert report["latencySeconds"]["max"] >= 0.5
        return dict(workers=workers, command=command, ledgers=ledgers, report=report)
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        server.close()
        await server.wait_closed()
        pending = list(peers)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


async def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shb", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    binary = args.shb.resolve(strict=True)
    result = dict(binary=str(binary), sha256=hashlib.sha256(binary.read_bytes()).hexdigest(), cases=[])
    # Create exclusively so evidence from an earlier run is never overwritten.
    with args.output.open("x") as output:
        try:
            for workers in (1, 2):
                result["cases"].append(await check(binary, workers))
        except Exception:
            result["failure"] = traceback.format_exc()
            raise
        finally:
            json.dump(result, output, indent=2)
            output.write("\n")
    print(f"PASS: independent H2 drain, 1/2 workers, {sum(r['report']['latencySamples'] for r in result['cases'])} exact samples")


if __name__ == "__main__":
    asyncio.run(main())
