import os

yolo_dir = r'D:\Uni\fyp\phantomnetui\phantomnetui\backend\yolov5'

for root, dirs, files in os.walk(yolo_dir):
    for fname in files:
        if not fname.endswith('.py'):
            continue
        fpath = os.path.join(root, fname)
        try:
            with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            if 'torch_load' not in content:
                continue
            content = content.replace(
                'from ultralytics.utils.patches import torch_load',
                '# from ultralytics.utils.patches import torch_load'
            )
            content = content.replace('torch_load(', 'torch.load(')
            with open(fpath, 'w', encoding='utf-8') as f:
                f.write(content)
            print('Fixed:', fpath)
        except Exception as e:
            print('SKIP:', fpath, '-', e)

print('Done!')
