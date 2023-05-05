from pdf2image import convert_from_path
from PIL import Image, ImageDraw
from typing import List, Tuple
import numpy as np
import cv2

from .redact_utils import pil_to_cv2, draw_black_box

from app.main.config import config

dbname = config.GetDBName()
tesserocr_path = config.GetOcrPath()

from app.main.util.db_utils import *
LoadDB = SQLConfig(Database=dbname)

Image.MAX_IMAGE_PIXELS = None  #for setting the max image pixel to be unbounded

#function to redact pdf based on entries and bounding boxes    
def pdf_redact(file_path, bound_box_list, redact_value, result_id, page_list):
    i = 1
    img_list = []
    remarks_list=[]

    pages = convert_from_path(file_path, 300)
    #creating a flag to search specific pages from db
    flag_list=[pg+1 if (pg+1 in page_list) else False for pg in range(len(pages))]
    for page in range(len(pages)):

        if page+1 in flag_list :
            indx_list = [index for (index, no) in enumerate(page_list) if no == page+1]
            page_bbox_list = [bound_box_list[i] for i in indx_list]
            page_redact_values = [redact_value[i] for i in indx_list]
            page_resultid_list = [result_id[i] for i in indx_list]

            if len(page_bbox_list)>0:
                img = pages[page]
                draw = ImageDraw.Draw(img)

                for i, words_bbox in enumerate(page_bbox_list):#bounding box redaction
                    page_redact_value_split = page_redact_values[i].split()
                    if len(words_bbox['value']) == len(page_redact_value_split):
                        #split the redact value for encoporating the redaction for all the list of boxes
                        for j, bbox in enumerate(words_bbox['value']):
                            draw_black_box(draw,bbox['left'],bbox['top'],bbox['width'],bbox['height'],page_redact_value_split[j]) 
                    else:
                        for bbox in words_bbox['value']:
                            draw_black_box(draw,bbox['left'],bbox['top'],bbox['width'],bbox['height'],page_redact_values[i])  
                    rs_id = page_resultid_list[i]
                    remarks_list.append([[rs_id,'Redaction Complete']])

                img = pil_to_cv2(img)
        else:
            img = pil_to_cv2(pages[page])
            #remarks_list.append([])

        img=cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
        img_list.append(img)   
 
    return img_list, remarks_list

#function to redact an image    
def image_redact(file_path, bound_box_list, redact_value, result_id):

    image=cv2.imread(file_path)
    img=Image.fromarray(image)
    draw = ImageDraw.Draw(img)

    remarks_list=[]

    if len(bound_box_list)>0:
        for i, bboxes in enumerate(bound_box_list):#bounding box redaction
            redact_value_split = redact_value[i].split()
            if len(bboxes['value']) == len(redact_value_split):
                #split the redact value for encoporating the redaction for all the list of boxes
                    for j, bbox in enumerate(bboxes['value']):
                        draw_black_box(draw,bbox['left'],bbox['top'],bbox['width'],bbox['height'],redact_value_split[j])
            else:
                for bbox in bboxes['value']:
                    draw_black_box(draw,bbox['left'],bbox['top'],bbox['width'],bbox['height'],redact_value[i])  
            rs_id = result_id[i]
            remarks_list.append([[rs_id,'Redaction Complete']])

    img = np.array(img)
    img = cv2.cvtColor(img, cv2.COLOR_BGR2RGB)
 
    return img, remarks_list