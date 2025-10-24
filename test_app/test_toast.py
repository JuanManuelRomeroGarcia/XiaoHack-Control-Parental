# test_toast.py
ok = False
try:
    from winsdk.windows.ui.notifications import ToastNotificationManager, ToastNotification
    from winsdk.windows.data.xml.dom import XmlDocument
    xml = XmlDocument()
    xml.load_xml("<toast><visual><binding template='ToastGeneric'>"
                 "<text>XiaoHack</text><text>WinRT OK</text></binding></visual></toast>")
    ToastNotificationManager.create_toast_notifier("XiaoHack").show(ToastNotification(xml))
    ok = True
except Exception as e:
    print("WinRT fallo:", e)

if not ok:
    try:
        from winotify import Notification
        Notification(app_id="XiaoHack", title="XiaoHack", msg="winotify OK").show()
        ok = True
    except Exception as e:
        print("winotify fallo:", e)

if not ok:
    try:
        from win10toast import ToastNotifier
        ToastNotifier().show_toast("XiaoHack", "win10toast OK", duration=3, threaded=True)
        ok = True
    except Exception as e:
        print("win10toast fallo:", e)

print("Resultado:", "OK" if ok else "Sin métodos disponibles")
