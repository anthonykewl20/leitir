import widgetlib


def rebind():
    global widgetlib
    widgetlib = None


rebind()
widgetlib.do_thing()
