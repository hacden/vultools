# -*- coding:utf-8 -*-
#written by hacden 2020/03/15
import turtle
import time
import re
from tkinter import messagebox
import tkinter
from pynput.mouse import *
import threading
from pynput import keyboard


class MY_GUI():
    def __init__(self):
        turtle.title('By_Hacden')
        turtle.setup(width=700, height=600)
        self.my_window = turtle.screensize(canvwidth=600, canvheight=500, bg="black")
        self.pwd = "hacden"
        self.xls_text = tkinter.StringVar()
    def __set_pen(self):
        turtle.color("lime")
        turtle.pensize(1)
        turtle.speed(0.5)
        turtle.hideturtle()
    def __move_pen(self,x,y):
        turtle.up()
        turtle.goto(x,y)
        turtle.down()
    def __show_text(self):
        x = -300
        y = 250
        my_text = "..............................................." \
                  "\n亲爱的xxxxx：" \
                  "\n→> xxxxxxxxxxxxxxxxxxxxxxxxxxxx缘分吧" \
                  "\n→> xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
                  "\n→> xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
                  "\n→> xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
                  "\n..............................................." \
                  "\n→> xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
                  "\n→> xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
                  "\n→> xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
                  "\n..............................................." \
                  "\n→> It's not easy to meet such a big world." \
                  "\n→> Until I met you" \
                  "\n→> I feel like I've got the right person，I like to think of you quietly. " \
                  "\n→> Although we haven't known each other for a long time, " \
                  "\n→> I cherish every day I chat with you. " \
                  "\n→> I feel happy and satisfied when we are together. " \
                  "\n→> xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
                  "\n→>............................By_Hacden" \

        for my_text in my_text:
            turtle.write(my_text, font=('Arial', 11), align="center")
            time.sleep(0.1)
            if re.findall("[a-zA-Z]", my_text):
                # turtle.write(my_text, font=('Arial', 10), align="center")
                x += 8
            else:
                if my_text == " ":
                    x += 7
                else:
                    x += 13
            self.__move_pen(x,y)
            if x>300 or my_text == "\n":
                x = -300
                y -= 15
                self.__move_pen(x,y)

    def __set_piture(self):
        turtle.color('red', 'pink')  # 画笔颜色
        for i in range(200):
            turtle.right(1)
            turtle.forward(1)

    def __show_piture(self):
        self.__move_pen(x=160, y=-250)  # 移动画笔位置
        turtle.left(130)  # 向左旋转140度
        turtle.begin_fill()  # 标记背景填充位置
        turtle.forward(110) # 向前移动画笔，长度为224

        self.__set_piture()
        turtle.left(120)  # 调整画笔角度
        self.__set_piture()

        turtle.forward(110)  # 向前移动画笔，长度为224
        turtle.end_fill()  # 标记背景填充结束位置

        self.__move_pen(180,-160)
        turtle.color('#CD5C5C', 'pink')  # 字体颜色
        # font:设定字体、尺寸（电脑下存在的字体都可设置）  align:中心对齐
        love = "I love you"
        x = 130
        for love in love:
            time.sleep(0.5)
            self.__move_pen(x,-160)
            x += 10
            turtle.write(love, font=('Arial', 15, 'bold'), align="center")

    def __show_mesbox(self):
        tkinter.Label(self.my_window, text="请输入密码启动：").pack()
        tkinter.Entry(self.my_window, textvariable=self.xls_text).pack()
        self.xls_text.set("")
        tkinter.Button(self.my_window, text="点击确认", command=self.__on_click).pack()

    def __on_click(self):
        if self.pwd == self.xls_text.get().strip():
            self.__run_print()
        else:
            messagebox.showerror(title="错误",message="密码错误，请重新输入")

    def __set_mouse(self):
        mouse = Controller()
        mouse.position = (680,670)
        while True:
            xy = list(mouse.position)
            print(xy)
            if 600 < xy[0] < 780 and 200 < xy[1] < 720:
                pass
            else:
                mouse.position = (680,670)
            if self.pwd == self.xls_text.get().strip():
                break
            time.sleep(0.2)

    # def __set_keyboard(self):
    #     def on_activate_h():
    #       self.run()
    #     while True:
    #         with keyboard.GlobalHotKeys({'<ctrl>+<alt>+<delete>': on_activate_h}) as h:
    #             h.join()

    def __run_print(self):
        self.__set_pen()
        self.__move_pen(x=-300, y=250)
        self.__show_text()
        self.__show_piture()

    def run(self):
        box = threading.Thread(target=self.__show_mesbox)
        box.start()
        mou = threading.Thread(target=self.__set_mouse)
        mou.start()
        # ketb = threading.Thread(target=self.__set_keyboard)
        # ketb.start()
        turtle.mainloop()


if __name__ == '__main__':
    my_gui = MY_GUI()
    my_gui.run()
