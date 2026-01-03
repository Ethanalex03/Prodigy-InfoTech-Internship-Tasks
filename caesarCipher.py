def caesarCipher(text, shift, mode='encrypt'):
    if mode == 'decrypt':
        shift = -shift
    result =[]
    for char in text:
        if char.isalpha():
            start = ord('A') if char.isupper() else ord('a')
            shifted = (ord(char)-start+shift) % 26
            result.append(chr(start + shifted))
        else:
            result.append(char)
    return ''.join(result)

def main():
    while True:
        print('Options')
        print('1. Encrypt')
        print('2. Decrypt')
        print('3. Exit')
        option = input("Enter your choice: (1-3)\n")
        if option == '3':
            break
        text = input("Enter your text: ")
        shift = int(input("Enter your shift: "))
        mode = 'encrypt' if option =='1' else 'decrypt'
        print(f"\nOriginal text: {text}")
        print(f"Cipher text: {caesarCipher(text, shift, mode)}")
if __name__ == '__main__':
    main()

