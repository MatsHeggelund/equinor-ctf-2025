import cv2, glob, os
import numpy as np

os.makedirs("tracked", exist_ok=True)

PDF_W = 506
PDF_H = 300

template = cv2.imread("template.png", cv2.IMREAD_GRAYSCALE)
th, tw = template.shape[:2]

for f in sorted(glob.glob("frames/*.png")):
    img = cv2.imread(f)
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    res = cv2.matchTemplate(gray, template, cv2.TM_CCOEFF_NORMED)
    _, _, _, max_loc = cv2.minMaxLoc(res)
    tx, ty = max_loc  # title bar top-left

    # crop starting at the titlebar from template.png
    x = tx
    y = ty
    crop = img[y:y+PDF_H, x:x+PDF_W]

    cv2.imwrite("tracked/" + os.path.basename(f), crop)
