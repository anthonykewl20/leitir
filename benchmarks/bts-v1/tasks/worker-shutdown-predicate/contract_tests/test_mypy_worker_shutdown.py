import librt.internal as ipc
from mypy.build import SCC_REQUEST_MESSAGE, SOURCES_DATA_MESSAGE
from mypy.build_worker.worker import should_shutdown
from mypy.cache import write_int_list


def _message(tag, values=()):
    writer = ipc.WriteBuffer()
    ipc.write_tag(writer, tag)
    write_int_list(writer, list(values))
    return ipc.ReadBuffer(writer.getvalue())


def test_expected_tag_returns_false():
    assert should_shutdown(_message(SOURCES_DATA_MESSAGE), SOURCES_DATA_MESSAGE) is False


def test_shutdown_request_returns_true():
    assert should_shutdown(_message(SCC_REQUEST_MESSAGE), SCC_REQUEST_MESSAGE) is True


def test_unexpected_tag_raises():
    try:
        should_shutdown(_message(SOURCES_DATA_MESSAGE), SCC_REQUEST_MESSAGE)
    except AssertionError:
        return
    raise AssertionError("unexpected worker message did not raise")
