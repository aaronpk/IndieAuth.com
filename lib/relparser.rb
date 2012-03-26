class RelParser

  def initialize(opts={})
    @agent = Mechanize.new {|agent|
      agent.user_agent_alias = "Mac Safari"
    }
    @url = opts
    @page = nil
  end

  def get(tag)
    links = []
    if @page.nil?
      @page = @agent.get @url
    end
    @page.links.each do |link|
      links << link.href if link.rel?("me")
    end
    links
  end
end
