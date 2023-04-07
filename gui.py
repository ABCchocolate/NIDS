from tkinter import *

# Tk 객체 생성
root = Tk()

# 리스트 박스 추가
listbox = Listbox(root)
listbox.pack()

# 리스트 박스에 아이템 추가
listbox.insert(END, "Item 1")
listbox.insert(END, "Item 2")
listbox.insert(END, "Item 3")

# Tk 객체 실행
root.mainloop()
