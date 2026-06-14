"""Small mxGraph (draw.io) XML element helpers shared by the diagram generators."""

import xml.etree.ElementTree as ET


def _cell(gp, **attrs):
    c = ET.SubElement(gp, "mxCell")
    for k,v in attrs.items(): c.set(k, str(v))
    return c

def _geo(cell, x=0, y=0, w=10, h=10, relative=None):
    kw = {"x":str(int(x)),"y":str(int(y)),
          "width":str(int(w)),"height":str(int(h)),"as":"geometry"}
    if relative is not None: kw["relative"] = str(relative)
    ET.SubElement(cell, "mxGeometry", **kw)
