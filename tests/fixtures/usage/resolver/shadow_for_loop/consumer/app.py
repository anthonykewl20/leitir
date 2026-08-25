import widgetlib

for widgetlib in range(3):  # noqa: F402 - deliberate shadow fixture
    print(widgetlib)

widgetlib.do_thing()
