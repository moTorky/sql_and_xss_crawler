class req:
    def __init__(self, url, params, method):
        self.url = url
        self.params = params
        self.method = method
    def __getstate__(self):
        return self.url, self.params, self.method
    def __setstate__(self, state):
        self.url, self.params, self.method = state
