import widgetlib

with open("x") as widgetlib:  # noqa: F811 - deliberate shadow fixture
    widgetlib.read()

widgetlib.do_thing()
