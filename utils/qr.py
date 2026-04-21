try:
    import qrcode

    def print_qr(data: str, label: str = None):
        """
        Prints a compact ASCII QR code to the terminal.
        Uses half-block Unicode characters for compact display.
        Designed for short data like fingerprints — stays small.
        No files are created — terminal display only.
        """

        if label:
            print(f"\n[QR — {label}]")
        else:
            print("\n[QR Code]")

        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=1,
            border=1,
        )
        qr.add_data(data)
        qr.make(fit=True)

        matrix = qr.get_matrix()

        # Half-block rendering — packs 2 QR rows into 1 terminal line
        # Halves vertical size for compact display
        for y in range(0, len(matrix), 2):
            line = ""
            for x in range(len(matrix[y])):
                top = matrix[y][x]
                bottom = matrix[y + 1][x] if y + 1 < len(matrix) else False

                if top and bottom:
                    line += "█"
                elif top and not bottom:
                    line += "▀"
                elif not top and bottom:
                    line += "▄"
                else:
                    line += " "
            print(line)

        print("\nScan with phone or print. No file saved.\n")

except ImportError:
    def print_qr(data: str, label: str = None):
        print("\n[QR Code unavailable — install qrcode library]\n")