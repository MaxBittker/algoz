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
 
    image = Image.open(BytesIO(raw)).convert('RGB')
    image = preprocess(image).unsqueeze(0).cpu() # [1, 3, 224, 224]
    image_onnx = image.detach().cpu().numpy().astype(np.float32)

    image_features = onnx_model.encode_image(image_onnx)
    # print(image_features.shape)

# list_data = 

# Now dump to JSON
# json_data = json.dumps(list_data)

    return {
            "file_size": len(raw), 
            "values": image_features.tolist()
    } 
    # Compute the raw similarity score
    # similarity = (100.0 * image_features @ text_features.T)
    # similarity_softmax = similarity.softmax(dim=-1)
    
    # Define a threshold
    # threshold = 10.0

    # Get the highest scoring category
    # max_raw_score = torch.max(similarity)
    # if max_raw_score < threshold:
    #     return {
    #         "file_size": len(raw), 
    #         "category": "none", 
    #         "similarity_score": 0,
    #         "values": [0.0 for _ in categories]
    #     }
    # else:
        # category_index = similarity_softmax[0].argmax().item()
        # category = categories[category_index]
        # similarity_score = similarity_softmax[0, category_index].item()
        # values = similarity[0].tolist()
        # return {
            # "file_size": len(raw), 
            # "category": category, 
            # "similarity_score": similarity_score,
            # "values": values
        # }


run(host='0.0.0.0', port=8181)

