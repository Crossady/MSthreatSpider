import scrapy
import requests


class ThreatSpider(scrapy.Spider):
    data_path = r'C:\Users\DFZ\PycharmProjects\MSthreatSpider\msthreatspider\msthreatspider\data'
    name = "threats"
    custom_settings = {
        'LOG_FILE': r'C:\Users\DFZ\PycharmProjects\MSthreatSpider\msthreatspider\log\exploits.log',
    }
    payload = {'query': 'Exploits',
               'page': 1,
               'showall': 'false',
               'sortby': 'relevance',
               'sortdir': 'desc',
               'size': '10'}
    totalPage = 1
    base_url = 'https://www.microsoft.com/en-us/wdsi/threats/threat-search'

    def start_requests(self):
        # while ThreatSpider.payload['page'] <= ThreatSpider.totalPage:
        #     ThreatSpider.payload['page'] += 1
        #     yield requests.get(ThreatSpider.base_url, params=ThreatSpider.payload).url
        url = requests.get(ThreatSpider.base_url, params=ThreatSpider.payload).url
        yield scrapy.Request(url, callback=self.parse)

    def parse(self, response):
        result_count = response.xpath("//div[@id='resultCount']//span/text()").extract()
        totalCount = int(result_count[0])
        ThreatSpider.totalPage = totalCount // 10 + 1

        for result in response.css('a.notranslate.resultset'):
            # name = result.css('a::text').extract_first()
            href = result.css('a::attr(href)').extract_first()
            yield response.follow(href, callback=self.parse_threat)
            # yield {
            #     'name': result.css('a::text').extract_first(),
            #     'href': result.css('a::attr(href)').extract_first(),
            # }

        ThreatSpider.payload['page'] += 1
        if ThreatSpider.payload['page'] <= ThreatSpider.totalPage:
            next_url = requests.get(ThreatSpider.base_url, params=ThreatSpider.payload).url
            yield scrapy.Request(next_url, callback=self.parse)

    def parse_threat(self, response):
        publish_date = response.xpath("//span[@id='publishDate']//text()").extract_first()
        update_date = response.css("span.descupd::text").extract_first()
        name = response.css("h1.c-heading-2.dont-change::text").extract_first()
        alert_level = response.css("strong::text").extract_first().strip()
        detect_with = response.css("a.c-hyperlink::text").extract_first()
        also_detect_as = [y.strip() for y in response.css("span.also-detected")[0].css("span::text").extract() if
                          not y.isspace()]

        entries = response.xpath("//div[@id='simpleDrawer']")
        summary = "".join([y for y in entries[0].xpath("*//text()").extract()])
        what_to_do_now = "".join([y for y in entries[1].xpath("*//text()").extract()])
        technical_information = "".join([y for y in entries[2].xpath("*//text()").extract()])
        symptoms = "".join([y for y in entries[3].xpath("*//text()").extract()])

        yield {
            'publish_date': publish_date,
            'update_date': update_date,
            'name': name,
            'alert_level': alert_level,
            'detect_with': detect_with,
            'also_detect_as': also_detect_as,
            'summary': summary,
            'what_to_do_now': what_to_do_now,
            'technical_information': technical_information,
            'symptoms': symptoms
        }
