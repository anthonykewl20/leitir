import sys

if sys.version_info >= (3, 8):  # noqa: UP036 - deliberate version-branch fixture
    import fastwidget as widgetlib
else:
    import widgetlib

widgetlib.do_thing()
