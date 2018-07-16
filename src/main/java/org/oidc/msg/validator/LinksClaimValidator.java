package org.oidc.msg.validator;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.oidc.msg.InvalidClaimException;
import org.oidc.msg.Link;

public class LinksClaimValidator implements ClaimValidator {

  @Override
  public Object validate(Object value) throws InvalidClaimException {
    if (value instanceof List) {
      List<?> list = (List<?>) value;
      List<Link> links = new ArrayList<Link>();
      MapClaimValidator mapValidator = new MapClaimValidator();
      for (Object item : list) {
        Map<String, Object> claims = (Map<String, Object>) mapValidator.validate(item);
        Link link = new Link(claims);
        // TODO: this is just for initiating verify()
        link.getClaims();
        links.add(link);
      }
      return links;
    }
    throw new InvalidClaimException(String.format("Parameter '%s' is not of expected type", value));
  }

}
