@Bean
public MappingJackson2HttpMessageConverter jsonConverter() {
  return new MappingJackson2HttpMessageConverter();
}
