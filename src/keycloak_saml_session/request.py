import requests

class MalformatedUrl(Exception):
    pass


class UnknownMethod(Exception):
    pass


class BadMethod(Exception):
    pass


class ParamsRequest:
    def __init__(self):
        self.param = {}

    def addParam(self, key, value):
        self.param[key] = value

    def build(self):
        return self.param

    def build_url(self):
        if len(self.param) == 0:
            return ""
        url = ""
        count = 0
        for key in self.param:
            if count == 0:
                url = url + key + "=" + self.param[key]
            else:
                url = url + "&" + key + "=" + self.param[key]
        return "?" + url


class Request:
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    call_methods = {
        "GET": requests.get,
        "POST": requests.post,
        "PUT": requests.put,
        "PATCH": requests.patch,
        "DELETE": requests.delete
    }

    def __init__(self, url, method, bearer=None):
        self.url = url
        self.method = method
        self.call_method = Request.call_methods[self.method]
        self.param = {}
        self.headers = {}
        self.body = ""
        self.bodyMimeType = ""
        self.response = None
        self.bearer_token = bearer
        self.check_method = lambda c: (c >= 200 and c <= 399)

    def addParam(self, key, value):
        self.param[key] = value

    def addParamObject(self, param):
        self.param = param.build()

    def addBody(self, value, mimeType):
        if self.method not in ["POST", "PUT", "PATCH"]:
            raise BadMethod(self.method)
        self.body = value
        self.bodyMimeType = mimeType

    def addHeader(self, key, value):
        self.headers[key] = value

    def do_request(self):
        if self.bearer_token is not None:
            self.headers["Authorization"] = "Bearer " + self.bearer_token
        if self.bodyMimeType != "":
            self.headers["Content-type"] = self.bodyMimeType
        self.response = self.call_method(self.url,
                                         params=self.param,
                                         data=self.body,
                                         headers=self.headers)
        return self.check_response()

    def get_raw(self):
        if self.response is None or self.check_empty():
            return None
        return self.response.text

    def get_json(self):
        if self.response is None or self.check_empty():
            return None
        return self.response.json()

    def build_url(self):
        uri = []
        for el in self.param:
            uri.append(el+"="+str(self.param[el]))
        if len(uri) > 0:
            if self.url[-1] == "/":
                return self.url + "?" + "&".join(uri)
            return self.url + "/?" + "&".join(uri)
        else:
            return self.url

    def check_response(self):
        return self.check_method(self.response.status_code)

    def check_empty(self):
        return self.response.text == ""