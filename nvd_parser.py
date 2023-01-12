import datetime
import nvdlib

# Example:
# request = nvdlib.searchCVE(pubStartDate='2022-12-30 00:00', pubEndDate='2022-12-30 23:59')
#
# The result will be a JSON array of objects.
#
# Available results:
# id, sourceIdentifier, published, lastModified, vulnstatus, descriptions (lang, value), metrics, weaknesses, configurations, references (url, source, tags), cpe, cwe (lang, value), url, v31score, v31vector, v31severity, v31exploitability, v31impactScore, score
#
# To print specific array: str(eachCVE.score[0])
# To print specific object: eachCVE.descriptions[0].value

today = datetime.datetime.now()
yesterday = today - datetime.timedelta(days=1)

request = nvdlib.searchCVE(pubStartDate=yesterday, pubEndDate=today)

resultFile = open("results.txt", "w")

isRussian = False

eng_headers = 'NUMBER;CVE ID;SOURCE;PUBLICATION DATE;LAST MODIFICATION;DESCRIPTION;REFERENCES\n'
ru_headers = 'Номер;CVE ID; Ресурс;Дата публикации;Последняя модификация;Описание;Ссылки\n'

en_header_result = "Total results found: "
ru_header_result = "Всего результатов найдено: "

resultFile.write(ru_headers if isRussian else eng_headers)
reference = ''


def format_time(time: str) -> str:
    return time.replace("T", " ")[:len(time) - 4]


def get_cve_content():
    if request == "[]":  # Todo: This one may fuck up horribly, test this condition before printing it here...
        print(
            "Yay, no CVE for today!")  # Todo: Halt program execution upon meeting with an error (i.e. nvd.nist.gov may throw "403 Forbidden" on api, then execution will die)
        return
    # Todo: Track last element and crop the \n new line thingy

    counter = 0
    for eachCVE in request:
        counter = counter + 1
        reference = str(eachCVE.references)
        if reference == '[]':
            reference = '<a href="' + 'https://nvd.nist.gov/vuln/detail/' + str(
                eachCVE.id) + '" target="_blank"' + '>' + (
                            "Больше информации" if isRussian else 'More info here') + '</a>'
        else:
            reference = '<a href="' + str(eachCVE.references[0].url) + '" target="_blank">' + \
                        ("Больше информации" if isRussian else 'More info here') + '</a>'
        resultFile.write(
            str(counter) + '|c_c|' +
            eachCVE.id + '|c_c|' +
            eachCVE.sourceIdentifier + '|c_c|' +
            format_time(eachCVE.published) + '|c_c|' +
            format_time(eachCVE.lastModified) + '|c_c|' +
            eachCVE.descriptions[0].value + '|c_c|' +
            reference + '\n')
    resultFile.close()
    return counter

def create_page():
    count_of_cve = get_cve_content() #получаем данные

    # Now we write into html file
    filein = open("results.txt", "r")
    fileout = open("CVE NEWS.html", "w")
    file_css = open("style.css", "r").read().rstrip()

    fileout.write("""
        <html>
            <head>
                <title>CVE News for today</title><link rel="stylesheet">
                <style>""" + file_css + """ </style> 
            </head>
                        <script src="https://www.kryogenix.org/code/browser/sorttable/sorttable.js"></script>
            <body>
                <h1>""" + (ru_header_result if isRussian else en_header_result) + str(count_of_cve) + """</h1>\n""")

    data = filein.readlines()

    table = '<table class="sortable">\n'

    # Create table's column headers
    header = data[0].split(";")
    table += '    <tr>\n'
    for column in header:
        table += '      <th style="cursor: pointer;">{0}</th>\n'.format(column.strip())
    table += '    </tr>\n'

    # Create table's row data
    for line in data[1:]:
        row = line.split("|c_c|")
        table += '    <tr  class="item">\n'
        for column in row:
            table += '      <td>{0}</td>\n'.format(column.strip())
        table += '    </tr>\n'
    table += '</table>'

    fileout.writelines(table)

    fileout.write("""</body></html>""")
    fileout.close()
    filein.close()



if __name__ == "__main__":
    create_page()
