import widgetlib


def risky():
    raise ValueError("boom")


try:
    risky()
except ValueError as widgetlib:
    print(widgetlib)

widgetlib.do_thing()
