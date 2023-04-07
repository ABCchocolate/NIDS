import tkinter as tk
import tkinter.filedialog as filedialog
from tensorflow.keras.models import load_model
import numpy as np

# 모델 로드
model = load_model('../NIDS-1/weights/mlp_multi.h5')

# GUI 애플리케이션 생성
root = tk.Tk()

# 파일 선택 대화상자 열기
def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        # 이미지 불러오기
        image = tk.PhotoImage(file=file_path)

        # 이미지 예측
        image_data = np.array(image)
        prediction = model.predict(image_data)

        # 예측 결과 출력
        print(prediction)

# 파일 선택 버튼 생성
button = tk.Button(root, text='Open File', command=open_file)
button.pack()

root.mainloop()