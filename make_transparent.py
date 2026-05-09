from PIL import Image

def make_white_transparent(input_path, output_path, tolerance=240):
    print(f"Processando {input_path}...")
    try:
        img = Image.open(input_path).convert("RGBA")
        datas = img.getdata()

        new_data = []
        for item in datas:
            # item is (R, G, B, A)
            if item[0] >= tolerance and item[1] >= tolerance and item[2] >= tolerance:
                # change all white (or close to white) to transparent
                new_data.append((255, 255, 255, 0))
            else:
                new_data.append(item)

        img.putdata(new_data)
        img.save(output_path, "PNG")
        print(f"Salvo em {output_path}")
    except Exception as e:
        print(f"Erro: {e}")

if __name__ == "__main__":
    make_white_transparent(
        r"C:\Users\iagop\.gemini\antigravity\brain\b84e0941-d43f-4fd5-bea3-92bfa0b3bc76\media__1778028188087.png",
        r"c:\Faculdade\AcheiNoCampus\frontend\src\assets\logo_no_bg_1.png"
    )
    make_white_transparent(
        r"C:\Users\iagop\.gemini\antigravity\brain\b84e0941-d43f-4fd5-bea3-92bfa0b3bc76\media__1778028188285.png",
        r"c:\Faculdade\AcheiNoCampus\frontend\src\assets\logo_no_bg_2.png"
    )
