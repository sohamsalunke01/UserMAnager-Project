package com.project.manager;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements UserDetailsService {

	@Autowired
	private UserRepository userRepo;

@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepo.findByEmail(username);
			if (user == null) {
				throw new UsernameNotFoundException("User not found");
				}
			return new CustomUserDetails(user);
}
@Autowired
private UserRepository repo;
 
public void processOAuthPostLogin(String username) {
    User existUser = repo.findByEmail(username);
     
    if (existUser == null) {
        User newUser = new User();
        newUser.setEmail(username);
        newUser.setProvider(Provider.GOOGLE);
        newUser.setEnabled(true);          
         
        repo.save(newUser);        
    }
     
}

}
