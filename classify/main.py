import time
from bottle import route, request, run
import onnxruntime
from PIL import Image
from io import BytesIO
import numpy as np
import clip
from clip_onnx import clip_onnx

import sentry_sdk

from sentry_sdk.integrations.bottle import BottleIntegration

sentry_sdk.init(
  dsn="https://345df77f6c61f24ac0977b02131d4d05@o40136.ingest.sentry.io/4505718094495744",
  integrations=[
    BottleIntegration(),
  ],
  # Set traces_sample_rate to 1.0 to capture 100%
  # of transactions for performance monitoring.
  # We recommend adjusting this value in production,
  traces_sample_rate=1.0,
)




# Load the CLIP model
device = "cpu"
model, preprocess = clip.load("ViT-B/32", device=device, jit=False)


visual_path = "clip_visual.onnx"
textual_path = "clip_textual.onnx"

onnx_model = clip_onnx(model, visual_path=visual_path, textual_path=textual_path)



onnx_model = clip_onnx(None)
onnx_model.load_onnx(visual_path="visual.onnx",
                     textual_path="textual.onnx",
                     logit_scale=100.0000) # model.logit_scale.exp()
onnx_model.start_sessions(providers=["CPUExecutionProvider"])



@route('/embed_image/', method='POST')
def embed_image():

    upload = request.files.get('upload')
    raw = upload.file.read()  # this is dangerous for big files
 
    # start timer:
    start = time.time() 

    image = Image.open(BytesIO(raw)).convert('RGB')
    image = preprocess(image).unsqueeze(0).cpu() # [1, 3, 224, 224]
    image_onnx = image.detach().cpu().numpy().astype(np.float32)

    image_features = onnx_model.encode_image(image_onnx)
    # print(image_features.shape)
    # print time elapsed in ms:
    print(round((time.time() - start)*1000), "ms")

    return {
            "file_size": len(raw), 
            "values": image_features.tolist()
    } 
   


run(host='0.0.0.0', port=8181)

