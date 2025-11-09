import cv2, numpy as np, glob

files = sorted(glob.glob("tracked/*.png"))
stack = [cv2.imread(f).astype(np.float32) for f in files]

arr = np.stack(stack, axis=0)
mean = arr.mean(axis=0)
mean = np.clip(mean, 0, 255).astype(np.uint8)

cv2.imwrite("mean.png", mean)
