import socketserver
import binascii

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024)
        print("{} wrote:".format(self.client_address[0]))
        get_msg = binascii.hexlify(self.data)
        print(get_msg.decode('utf-8'))
        # just send back the same data, but upper-cased
        self.request.sendall("Allive-Only".encode('utf-8'))

if __name__ == "__main__":
    HOST, PORT = "127.0.0.1", 80

    # Create the server, binding to localhost on port 9999
    with socketserver.TCPServer((HOST, PORT), MyTCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        server.serve_forever()










""""
def parse_html_class_names(old_html: string,
                           equivalents_obfuscated_html_classes: Dict,
                           class_generator: Callable[[Dict],
                                                     str]) -> Tuple:


    # Regex to fetch HTML classes in the file
    html_class_regex = r"class=[\"\']?((?:.(?![\"\']?\s+(?:\S+)=|\s*\/?[>\"\']))+.)[\"\']?"

    # classes_groups can be ['navbar p-5', 'navbar-brand', 'navbar-item',
    # 'title is-4']
    classes_groups = re.findall(html_class_regex, old_html)
    obfuscate_classes_groups = []

    for i, classes in enumerate(classes_groups):
        div_of_classes = classes.split()
        obfuscate_classes_groups.append([])

        for old_class_name in div_of_classes:
            if old_class_name not in equivalents_obfuscated_html_classes:
                equivalents_obfuscated_html_classes[old_class_name] = class_generator(
                    equivalents_obfuscated_html_classes)
            obfuscate_classes_groups[i].append(
                equivalents_obfuscated_html_classes[old_class_name])

    for i, classes in enumerate(obfuscate_classes_groups):
        obfuscate_classes_groups[i] = " ".join(classes)

    return (
        classes_groups,
        obfuscate_classes_groups,
        equivalents_obfuscated_html_classes)


def generate_html(
        html_content: str = "",
        classes_groups: Dict = (),
        obfuscate_classes_groups: Dict = ()) -> str:


    for i, classes_group in enumerate(classes_groups):

        old_no_quote = "class=" + classes_group
        old_with_simple_quote = "class='" + classes_group + "'"
        old_with_double_quote = 'class="' + classes_group + '"'

        # Check if we need to generate quotes or not for the attributes
        # class=test_1
        # class="test_1 test_2"
        if len(obfuscate_classes_groups[i].split()) > 1:
            replace_by = 'class="' + obfuscate_classes_groups[i] + '"'
        else:
            replace_by = 'class=' + obfuscate_classes_groups[i] + ''

        # Replace like : class=navbar-item by class="{{ obfuscate_classes_groups }}"
        # Or replace like : class="navbar p-5" (with quote this time)
        html_content = html_content.replace(old_no_quote, replace_by)
        html_content = html_content.replace(old_with_simple_quote, replace_by)
        html_content = html_content.replace(old_with_double_quote, replace_by)

    return html_content


def generate_css(css_content: str = "", equivalent_class: Dict = ()) -> str:


    # We sort by the key length ; to first replace long classes names and after short one
    # ".navbar-brand", and then ".navbar" avoid "RENAMED_CLASS-brand" and "RENAMED_CLASS" bug
    for old_class_name in sorted(equivalent_class, key=len, reverse=True):
        new_class_name = equivalent_class[old_class_name]

        # CSS classes modifications
        # Example: a class like "lg:1/4" should be "lg\:1\/4" in CSS
        list_char_to_escape = {"!", "\"", "#", "$", "&", "'", "(", ")", "*", "+", ".", "/", ":", ";", "<", "=", ">", "?", "@", "[", "]", "^", "`", "{", "|", "}", "~","%"}

        # No need to escape "-"

        for char in list_char_to_escape:
            old_class_name = old_class_name.replace(char, "\\" + char)

        # Tailwind's way to escape "," :
        old_class_name = old_class_name.replace(",", "\\2c ")

        css_content = css_content.replace(
            "." + old_class_name, "." + new_class_name)
    return css_content


def generate_js(js_content: str = "", equivalent_class: Dict = ()) -> str:


    # We sort by the key length ; to first replace long classes names and after short one
    # ".navbar-brand", and then ".navbar" avoid "RENAMED_CLASS-brand" and "RENAMED_CLASS" bug
    for old_class_name in sorted(equivalent_class, key=len, reverse=True):
        new_class_name = equivalent_class[old_class_name]

        # JS modifications
        # document.querySelectorAll(".navbar-burger")
        # myDiv.classList.toggle("is-active")
        js_content = js_content.replace(
            '.querySelector(".' + old_class_name + '")',
            '.querySelector(".' + new_class_name + '")')
        js_content = js_content.replace(
            '.querySelectorAll(".' + old_class_name + '")',
            '.querySelectorAll(".' + new_class_name + '")')
        js_content = js_content.replace(
            '.classList.toggle("' + old_class_name + '")',
            '.classList.toggle("' + new_class_name + '")')

    return js_content


def html_classes_obfuscator(htmlfiles=None, cssfiles=None, jsfiles=None, class_generator: Callable[[
                            Dict], str] = lambda _: "_" + str(uuid.uuid4())):


    # Dict<HTMLClasses, ObfuscatedHTMLClasses>
    equivalents_obfuscated_html_classes = {}
    new_html, new_css, new_js = ['', '', '']
    # HTML FILES GENERATION : Fetch HTML classes and rename them
    with open(htmlfiles, "rb") as file:
            old_html = file.read().decode()

            # Fetch and parse the HTML file
            (
                classes_groups,
                obfuscate_classes_groups,
                equivalents_obfuscated_html_classes) = parse_html_class_names(
                old_html,
                equivalents_obfuscated_html_classes,
                class_generator)

            # obfuscate_classes_groups :
            # Shoud be [['test_1', 'test_2'], ['test_3'], ['test_4'],
            # ['test_5', 'test_6']]

            # --------------------------------------------------

            new_html = generate_html(
                old_html, classes_groups, obfuscate_classes_groups)

            #file.seek(0)
            #file.write(new_html)
            #file.truncate()

    # CSS FILES GENERATION
    if cssfiles:
        with open(cssfiles, "rb") as file:

            old_css = file.read().decode()
            new_css = generate_css(
                old_css, equivalents_obfuscated_html_classes)

    # JS FILES GENERATION
    if jsfiles:
        with open(jsfiles, "rb") as file:
            old_js = file.read().decode()
            new_js = generate_js(
                old_js, equivalents_obfuscated_html_classes)
    return new_html, new_css, new_js

def get_files() -> Dict:
    """Get the source files
    Returns:
        Dict: Dict of the source files
    """
    return {
        "htmlfiles": glob.glob(flags_command_line['htmlpath'], recursive=True),
        "cssfiles": glob.glob(flags_command_line['csspath'], recursive=True),
        "jsfiles": glob.glob(flags_command_line['jspath'], recursive=True),
    }




""""