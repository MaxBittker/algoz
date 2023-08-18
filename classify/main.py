import time
import threading
from bottle import route, request, run
import onnxruntime
from PIL import Image
from io import BytesIO
import numpy as np
import clip
from clip_onnx import clip_onnx

# Load the CLIP model
device = "cpu"
model, preprocess = clip.load("ViT-B/32", device=device, jit=False)

onnx_model = clip_onnx(None)
onnx_model.load_onnx(visual_path="visual.onnx",
                     textual_path="textual.onnx",
                     logit_scale=100.0000)  # model.logit_scale.exp()
onnx_model.start_sessions(providers=["CPUExecutionProvider"])

# stats vars
request_count = 0
total_request_time = 0.0

@route('/embed_image/', method='POST')
def embed_image():
    global request_count, total_request_time

    upload = request.files.get('upload')
    raw = upload.file.read()  # this is dangerous for big files

    # start timer:
    start = time.time()

    image = Image.open(BytesIO(raw)).convert('RGB')
    image = preprocess(image).unsqueeze(0).cpu()  # [1, 3, 224, 224]
    image_onnx = image.detach().cpu().numpy().astype(np.float32)

    image_features = onnx_model.encode_image(image_onnx)

    # calculate time elapsed in ms and update stats vars:
    elapsed = round((time.time() - start) * 1000)
    total_request_time += elapsed
    request_count += 1

    return {
        "file_size": len(raw),
        "values": image_features.tolist()
    }


# print stats every 30 sec:
def print_stats():
    while True:
        global request_count, total_request_time
        if request_count > 0:
            print(f"Requests per minute: {request_count * 2}")
            print(f"Average time per request: {round(total_request_time / request_count)} ms")
            # Reset the counters
            request_count = 0
            total_request_time = 0.0
        time.sleep(30)

# Start the stats thread
stats_thread = threading.Thread(target=print_stats)
stats_thread.start()

# Start the server
run(host='0.0.0.0', port=8181)