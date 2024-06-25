package com.form.Service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.form.Entity.Users;
import com.form.Repository.UsersRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	@Autowired
	private UsersRepository usersRepository;

	@Autowired
	BCryptPasswordEncoder bCryptPasswordEncoder;

	@Override
	public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
		List<Users> usersList = usersRepository.findUser(userName);
		System.out.println(userName);
		if (usersList != null && usersList.size() == 1) {
			Users users = usersList.get(0);
				System.out.print(users.getUserId());
			List<SimpleGrantedAuthority> authorities = users.getRoles().stream()
					.map(role -> new SimpleGrantedAuthority(role.name()))
					.collect(Collectors.toList());

			return User.builder()
					.username(users.getUsername())
					.password(users.getPassword()) // Password should already be encoded in the database
					.disabled(users.isDisabled())
					.accountExpired(users.isAccountExpired())
					.accountLocked(users.isAccountLocked())
					.credentialsExpired(users.isCredentialsExpired())
					.authorities(authorities)
					.build();
		} else {
			throw new UsernameNotFoundException("User Name not Found");
		}
	}
}